Digital Shadows monitors and manages an organization's digital risk across the widest range of data sources within the open, deep, and dark web.
## Configure Digital Shadows on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Digital Shadows.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| server | Server URL | True |
| apikey | API Key | True |
| secret | Secret | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| isFetch | Fetch incidents | False |
| incidentType | Incident type | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### ds-get-breach-reviews
***
Retrieve all review updates for a given data breach record


#### Base Command

`ds-get-breach-reviews`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| breach_id | Unique id of the data breach record to retrieve the status history for | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DigitalShadows.BreachReviews.Note | unknown | The note at this version \(max length 500 characters\) | 
| DigitalShadows.BreachReviews.Version | unknown | Starts counting at 1 and increments for each review of a given data breach credential. Will initially be 0 until a review is performed \(when returned as part of a credential\) | 
| DigitalShadows.BreachReviews.Status | unknown | Review status | 
| DigitalShadows.BreachReviews.UserID | unknown | ID of user that changed the status/set the note | 
| DigitalShadows.BreachReviews.UserRole | unknown | Role of user that changed the status/set the note | 
| DigitalShadows.BreachReviews.UserPermissions | unknown | Permissins of user that changed the status/set the note | 
| DigitalShadows.BreachReviews.UserEmail | unknown | Email address of user that changed the status/set the note | 
| DigitalShadows.BreachReviews.CreatedAt | unknown | The moment in time the review was created | 


### ds-snapshot-breach-status
***
Snapshot the review status of a data breach record


#### Base Command

`ds-snapshot-breach-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| note | The note at this version (max length 500 characters). | Optional | 
| status | Review status. | Required | 
| version | When submitting, this value can be optionally set to the version of the most recently read review | Optional | 
| breach_id | Unique id of the data breach record to submit a status update for | Required | 


#### Context Output

There is no context output for this command.


### ds-find-breach-records
***
Find data breach records


#### Base Command

`ds-find-breach-records`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pagination_containingId | Select the page containing the record with this id, if supported. Mutually exclusive with offset. | Optional | 
| pagination_offset | Include results at this offset within the full resultset, where the first result is at position 0 | Optional | 
| pagination_size | Maximum number of results to return per page, can be initially null to be replaced by default later | Optional | 
| sort_direction | The direction of sorting. If not specified, ASCENDING is assumed | Optional | 
| sort_property | The name of the property being sorted on. This normally corresponds to the property name of the result type, but could be a 'virtual property'. | Optional | 
| filter_distinction | Narrow down to records based on how unique their username and/or password are. | Optional | 
| filter_domainNames | Only records that are related to these domain names | Optional | 
| filter_password | Records that match this password, use '' for wildcard matching, '\' to find an actual asterisk. | Optional | 
| filter_published | Narrow down to records based on when they were published | Optional | 
| filter_reviewStatuses | List of statuses to include. Possible values are OPEN CLOSED IGNORED | Optional | 
| filter_username | Records that match this username, use '*' for wildcard matching. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DigitalShadows.BreachRecords.Content | unknown | The row content of this data breach record \(a line from a csv file, for example\) | 
| DigitalShadows.BreachRecords.Id | unknown | Identifier for this data breach record | 
| DigitalShadows.BreachRecords.Password | unknown | The password found in the breach record, if any could be found | 
| DigitalShadows.BreachRecords.DomainNames | unknown | The domain names identified within the breach row | 
| DigitalShadows.BreachRecords.PriorRowTextBreachCount | unknown | The number of breaches the entire text of the breach row has appeared in prior to the current breach | 
| DigitalShadows.BreachRecords.PriorUsernameBreachCount | unknown | The number of breaches this username appeared in prior to the current breach | 
| DigitalShadows.BreachRecords.PriorUsernamePasswordBreachCount | unknown | The number of breaches this username/password combination have appeared in prior to the current breach | 
| DigitalShadows.BreachRecords.Published | unknown | When did this record become available | 
| DigitalShadows.BreachRecords.Review.Created | unknown | The moment in time the review was created. | 
| DigitalShadows.BreachRecords.Review.Status | unknown | Review status | 
| DigitalShadows.BreachRecords.Review.User.id | unknown | Unique id of user | 
| DigitalShadows.BreachRecords.Review.User.fullName | unknown | Full name of the user | 
| DigitalShadows.BreachRecords.Review.User.emailAddress | unknown | Email address of the user | 
| DigitalShadows.BreachRecords.Username | unknown | A best effort to identify a username within the content of the breach record | 
| DigitalShadows.BreachRecords.DataBreachId | unknown | The data breach this record belongs to | 


#### Command Example
```!ds-find-breach-records pagination_size=2```

#### Context Example
```json
{
    "DigitalShadows": {
        "BreachRecords": [
            {
                "Content": "A",
                "DataBreachId": 99000001,
                "DomainNames": [
                    "demisto.com"
                ],
                "Id": 140260931001,
                "Password": "1",
                "PriorRowTextBreachCount": null,
                "PriorUsernameBreachCount": 0,
                "PriorUsernamePasswordBreachCount": 0,
                "Published": "2019-05-30T20:52:59.489Z",
                "Review": {
                    "Created": null,
                    "Status": "OPEN",
                    "User": null
                },
                "Username": "some_mail@mail.com"
            },
            {
                "Content": "B",
                "DataBreachId": 99000002,
                "DomainNames": [
                    "demisto.com"
                ],
                "Id": 140261100001,
                "Password": "2",
                "PriorRowTextBreachCount": null,
                "PriorUsernameBreachCount": 0,
                "PriorUsernamePasswordBreachCount": 0,
                "Published": "2019-05-30T20:53:00.635Z",
                "Review": {
                    "Created": null,
                    "Status": "OPEN",
                    "User": null
                },
                "Username": "another_mail@mail.com"
            }
        ]
    }
}
```

#### Human Readable Output

>### Digital Shadows Breach Records
> Content| DataBreachId| DomainNames| Id| Password| PriorRowTextBreachCount| PriorUsernameBreachCount| PriorUsernamePasswordBreachCount| Published| Review Created| Review Status| Review User| Username
>---|---|---|---|---|---|---|---|---|---|---|---|---
>A | 99000001 | demisto.com | 140260931001 | 1 |   | 0 | 0 | 2019-05-30T20:52:59.489Z |   | OPEN |   | some_mail@mail.com
>aB | 99000002 | demisto.com | 140261100001 | 2 |   | 0 | 0 | 2019-05-30T20:53:00.635Z |   | OPEN |   | another_mail@mail.com


### ds-get-breach-summary
***
Summary of all data breaches for the current client


#### Base Command

`ds-get-breach-summary`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.

#### Command Example
```!ds-get-breach-summary```

#### Context Example
```json
{}
```

#### Human Readable Output

>{"breachesPerDomain":[{"count":3,"key":"molnnet.com"}],"totalBreaches":3,"totalUsernames":238,"usernamesPerDomain":[{"count":238,"key":"demisto.com"}]}

### ds-find-breach-usernames
***
Find unique usernames found across all data breaches


#### Base Command

`ds-find-breach-usernames`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pagination_containingId | Select the page containing the record with this id, if supported. Mutually exclusive with offset. | Optional | 
| pagination_offset | Include results at this offset within the full resultset, where the first result is at position 0 | Optional | 
| pagination_size | Maximum number of results to return per page, can be initially null to be replaced by default later | Optional | 
| sort_direction | The direction of sorting. If not specified, ASCENDING is assumed | Optional | 
| sort_property | The name of the property being sorted on. This normally corresponds to the property name of the result type, but could be a 'virtual property'. | Optional | 
| filter_domainNames | Only records that are related to these domain names | Optional | 
| filter_published | Narrow down to records based on when they were published | Optional | 
| filter_reviewStatuses | List of statuses to include. Possible values are OPEN CLOSED IGNORED | Optional | 
| filter_username | Records that match this username, use '*' for wildcard matching. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DigitalShadows.Users.BreachCount | unknown | The number of data breaches this username has appeared on | 
| DigitalShadows.Users.DistinctPasswordCount | unknown | The number of distict passwords encountered for this user | 
| DigitalShadows.Users.Username | unknown | The username that this summary is for | 


#### Command Example
```!ds-find-breach-usernames pagination_size=2```

#### Context Example
```json
{
    "DigitalShadows": {
        "Users": [
            {
                "BreachCount": 1,
                "DistinctPasswordCount": 1,
                "Username": "mail1@mail.com"
            },
            {
                "BreachCount": 1,
                "DistinctPasswordCount": 1,
                "Username": "mail2@mail.com"
            }
        ]
    }
}
```

#### Human Readable Output

>### Digital SHadows Breach Reviews
> BreachCount| DistinctPasswordCount| Username
>---|---|---
>1 | 1 | mail1@mail.com
>1 | 1 | mail2@mail.com


### ds-get-breach
***
Retrieve a data breach by its id


#### Base Command

`ds-get-breach`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| breach_id | Id of the data breach to retrieve | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DigitalShadows.Breaches.DomainCount | unknown | Number of unique domains contained in the breach. | 
| DigitalShadows.Breaches.DomainName | unknown | The domain the data breach occurred against | 
| DigitalShadows.Breaches.DataClasses | unknown | Data types contained within the breach | 
| DigitalShadows.Breaches.Id | unknown | Unique identifier for a breach | 
| DigitalShadows.Breaches.IncidentId | unknown | The ID of the incident raised for the breach, most specific to the client. | 
| DigitalShadows.Breaches.IncidentScope | unknown | The scope of the incident raised for the breach, most specific to the client. | 
| DigitalShadows.Breaches.IncidentSeverity | unknown | The severity of the incident raised for the breach, most specific to the client. | 
| DigitalShadows.Breaches.IncidentTitle | unknown | The title of the incident raised for the breach, most specific to the client. | 
| DigitalShadows.Breaches.IncidentType | unknown | The type of the incident raised for the breach, most specific to the client. | 
| DigitalShadows.Breaches.Occurred | unknown | Date the breach occurred | 
| DigitalShadows.Breaches.RecordCount | unknown | Number of records contained in the breach | 
| DigitalShadows.Breaches.SourceUrl | unknown | The url the data breach was found on | 
| DigitalShadows.Breaches.Title | unknown | The title assigned to this data breach | 


#### Command Example
```!ds-get-breach breach_id=99000001```

#### Context Example
```json
{
    "DigitalShadows": {
        "Breaches": {
            "DataClasses": [
                "EMAIL_ADDRESSES",
                "PASSWORDS"
            ],
            "DomainCount": 3372,
            "DomainName": "demisto.com",
            "Id": 99000001,
            "IncidentId": 99002706,
            "IncidentScope": "ORGANIZATION",
            "IncidentSeverity": "HIGH",
            "IncidentTitle": "Report of data leak from demisto.com",
            "IncidentType": "DATA_LEAKAGE",
            "Occurred": "2016-07-03",
            "RecordCount": 5846,
            "SourceUrl": "some_url",
            "Title": "Report of data leak from demisto.com"
        }
    }
}
```

#### Human Readable Output

>### Digital Shadows Breaches
> DataClasses| DomainCount| DomainName| Id| IncidentId| IncidentScope| IncidentSeverity| IncidentTitle| IncidentType| Occurred| RecordCount| SourceUrl| Title
>---|---|---|---|---|---|---|---|---|---|---|---|---
>EMAIL_ADDRESSES,PASSWORDS | 3372 | demisto.com | 99000001 | 99002706 | ORGANIZATION | HIGH | Report of data leak from demisto.com | DATA_LEAKAGE | 2016-07-03 | 5846 | some_url | Report of data leak from demisto.com


### ds-get-breach-records
***
Find data breach records


#### Base Command

`ds-get-breach-records`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| breach_id | Unique id of the data breach to retrieve records for | Required | 
| pagination_containingId | Select the page containing the record with this id, if supported. Mutually exclusive with offset. | Optional | 
| pagination_offset | Include results at this offset within the full resultset, where the first result is at position 0 | Optional | 
| pagination_size | Maximum number of results to return per page, can be initially null to be replaced by default later | Optional | 
| sort_direction | The direction of sorting. If not specified, ASCENDING is assumed | Optional | 
| sort_property | The name of the property being sorted on. This normally corresponds to the property name of the result type, but could be a 'virtual property'. | Optional | 
| filter_distinction | Narrow down to records based on how unique their username and/or password are. | Optional | 
| filter_domainNames | Only records that are related to these domain names | Optional | 
| filter_password | Records that match this password, use '' for wildcard matching, '\' to find an actual asterisk. | Optional | 
| filter_published | Narrow down to records based on when they were published | Optional | 
| filter_reviewStatuses | List of statuses to include. Possible values are OPEN CLOSED IGNORED | Optional | 
| filter_username | Records that match this username, use '*' for wildcard matching. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DigitalShadows.BreachRecords.Id | unknown | Identifier for this data breach record | 
| DigitalShadows.BreachRecords.Password | unknown | The password found in the breach record, if any could be found | 
| DigitalShadows.BreachRecords.PriorRowTextBreachCount | unknown | The number of breaches the entire text of the breach row has appeared in prior to the current breach | 
| DigitalShadows.BreachRecords.PriorUsernameBreachCount | unknown | The number of breaches this username appeared in prior to the current breach | 
| DigitalShadows.BreachRecords.PriorUsernamePasswordBreachCount | unknown | The number of breaches this username/password combination have appeared in prior to the current breach | 
| DigitalShadows.BreachRecords.Published | unknown | When did this record become available | 
| DigitalShadows.BreachRecords.Review.Created | unknown | The most recent review for this record | 
| DigitalShadows.BreachRecords.Review.Status | unknown | The status of the most recent review for this record | 
| DigitalShadows.BreachRecords.Review.User | unknown | The user who created the most recent review for this record | 
| DigitalShadows.BreachRecords.Username | unknown | A best effort to identify a username within the content of the breach record | 


#### Command Example
```!ds-get-breach-records breach_id=99000001 pagination_size=2```

#### Context Example
```json
{
    "DigitalShadows": {
        "BreachRecords": [
            {
                "Id": 140260931001,
                "Password": "1",
                "PriorRowTextBreachCount": null,
                "PriorUsernameBreachCount": 0,
                "PriorUsernamePasswordBreachCount": 0,
                "Published": "2019-05-30T20:52:59.489Z",
                "Review": {
                    "Created": null,
                    "Status": "OPEN",
                    "User": null
                },
                "Username": "some_mail@mail.com"
            },
            {
                "Id": 140260944001,
                "Password": "2",
                "PriorRowTextBreachCount": null,
                "PriorUsernameBreachCount": 0,
                "PriorUsernamePasswordBreachCount": 0,
                "Published": "2019-05-30T20:52:59.489Z",
                "Review": {
                    "Created": null,
                    "Status": "OPEN",
                    "User": null
                },
                "Username": "another_mail@mail.com"
            }
        ]
    }
}
```

#### Human Readable Output

>### Digital Shadows Breach Records
> Id| Password| PriorRowTextBreachCount| PriorUsernameBreachCount| PriorUsernamePasswordBreachCount| Published| Review Created| Review Status| Review User| Username
>---|---|---|---|---|---|---|---|---|---
>140260931001 | 1 |   | 0 | 0 | 2019-05-30T20:52:59.489Z |   | OPEN |   | some_mail@mail.com
>140260944001 | 2 |   | 0 | 0 | 2019-05-30T20:52:59.489Z |   | OPEN |   | another_mail@mail.com


### ds-find-data-breaches
***
Find data breaches


#### Base Command

`ds-find-data-breaches`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pagination_containingId | Select the page containing the record with this id, if supported. Mutually exclusive with offset. | Optional | 
| pagination_offset | Include results at this offset within the full resultset, where the first result is at position 0 | Optional | 
| pagination_size | Maximum number of results to return per page, can be initially null to be replaced by default later | Optional | 
| sort_direction | The direction of sorting. If not specified, ASCENDING is assumed | Optional | 
| sort_property | The name of the property being sorted on. This normally corresponds to the property name of the result type, but could be a 'virtual property'. | Optional | 
| filter_alerted | Only include data breaches with associated incidents that have been alerted | Optional | 
| filter_domainNamesOnRecords | List of domain names to filter by. Only data breaches that have one or more records attributed to this domain name | Optional | 
| filter_minimumTotalRecords | Only include data breaches that have at least this many total records (inclusive) | Optional | 
| filter_published | Narrow down to records based on when they were published | Optional | 
| filter_repostedCredentials | Filter out breaches depending on whether they consist entirely of reposted credentials or not. ORIGINAL or REPOST | Optional | 
| filter_severities | Only include data breaches with associated incidents having one of these severities, if not specified, all are considered | Optional | 
| filter_statuses | List of statuses to filter by. Pssible values:UNREAD, READ, CLOSED. | Optional | 
| filter_username | Only show breaches that include this username | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DigitalShadows.Breaches.DomainCount | unknown | Number of unique domains contained in the breach | 
| DigitalShadows.Breaches.DomainName | unknown | The domain the data breach occurred against | 
| DigitalShadows.Breaches.DataClasses | unknown | Data types contained within the breach | 
| DigitalShadows.Breaches.Id | unknown | Unique identifier for a breach | 
| DigitalShadows.Breaches.IncidentId | unknown | The ID of the incident raised for the breach, most specific to the client. | 
| DigitalShadows.Breaches.IncidentScope | unknown | The Scope of the incident raised for the breach, most specific to the client. | 
| DigitalShadows.Breaches.IncidentSeverity | unknown | The severity of the incident raised for the breach, most specific to the client. | 
| DigitalShadows.Breaches.IncidentTitle | unknown | The title of the incident raised for the breach, most specific to the client. | 
| DigitalShadows.Breaches.IncidentType | unknown | The type of the incident raised for the breach, most specific to the client. | 
| DigitalShadows.Breaches.Occurred | unknown | Date the breach occurred | 
| DigitalShadows.Breaches.Modified | unknown | When was this breach last modified | 
| DigitalShadows.Breaches.RecordCount | unknown | Number of records contained in the breach | 
| DigitalShadows.Breaches.SourceUrl | unknown | The url the data breach was found on | 
| DigitalShadows.Breaches.Title | unknown | The title assigned to this data breach | 
| DigitalShadows.Breaches.OrganisationUsernameCount | unknown | The number of distict usernames found that belong to the current organisation | 


#### Command Example
```!ds-find-data-breaches pagination_size=2```

#### Context Example
```json
{
    "DigitalShadows": {
        "Breaches": [
            {
                "DataClasses": null,
                "DomainCount": 3372,
                "DomainName": "demisto.com",
                "Id": 99000001,
                "IncidentId": 99002706,
                "IncidentScope": "ORGANIZATION",
                "IncidentSeverity": "HIGH",
                "IncidentTitle": "Report of data leak from demisto.com",
                "IncidentType": "DATA_LEAKAGE",
                "Modified": "2018-07-24T18:24:59.449Z",
                "Occurred": "2016-07-03",
                "OrganisationUsernameCount": 100,
                "RecordCount": 5846,
                "SourceUrl": "some_url",
                "Title": "Report of data leak from demisto.com"
            },
            {
                "DataClasses": null,
                "DomainCount": 5848,
                "DomainName": "someDomain.com",
                "Id": 99000000,
                "IncidentId": 99002728,
                "IncidentScope": "ORGANIZATION",
                "IncidentSeverity": "HIGH",
                "IncidentTitle": "Report of data leak from someDomain.com",
                "IncidentType": "DATA_LEAKAGE",
                "Modified": "2018-07-24T18:22:42.780Z",
                "Occurred": "2016-06-29",
                "OrganisationUsernameCount": 100,
                "RecordCount": 5858,
                "SourceUrl": "another_url",
                "Title": "Report of data leak from someDomain.com"
            }
        ]
    }
}
```

#### Human Readable Output

>### Digital Shadows Breaches
> DataClasses| DomainCount| DomainName| Id| IncidentId| IncidentScope| IncidentSeverity| IncidentTitle| IncidentType| Modified| Occurred| OrganisationUsernameCount| RecordCount| SourceUrl| Title
>---|---|---|---|---|---|---|---|---|---|---|---|---|---|---
>  | 3372 | demisto.com | 99000001 | 99002706 | ORGANIZATION | HIGH | Report of data leak from demisto.com | DATA_LEAKAGE | 2018-07-24T18:24:59.449Z | 2016-07-03 | 100 | 5846 | some_url | Report of data leak from demisto.com
>  | 5848 | someDomain.com | 99000000 | 99002728 | ORGANIZATION | HIGH | Report of data leak from someDomain.com | DATA_LEAKAGE | 2018-07-24T18:22:42.780Z | 2016-06-29 | 100 | 5858 | another_url | Report of data leak from someDomain.com


### ds-get-incident
***
Retrieve an incident by its id


#### Base Command

`ds-get-incident`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Identifier of the incident | Required | 
| fulltext | Show full text results | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DigitalShadows.Incidents.Alerted | unknown | The moment this incident was brought to the attention of the client | 
| DigitalShadows.Incidents.Description | unknown | Plain text description of this incident | 
| DigitalShadows.Incidents.ImpactDescription | unknown | Description of what impact the incident will have | 
| DigitalShadows.Incidents.Id | unknown | Identifier for this incident, unique in combination with the scope | 
| DigitalShadows.Incidents.Internal | unknown | Will be true if domain belongs to your organization \(as defined by the assets\), false otherwise | 
| DigitalShadows.Incidents.Mitigation | unknown | Information about what can be done to mitigate the effect of the problem | 
| DigitalShadows.Incidents.Occurred | unknown | Best effort to establish when the incident occurre | 
| DigitalShadows.Incidents.Modified | unknown | When was this incident last modified | 
| DigitalShadows.Incidents.Scope | unknown | Identifies whether this incident applies globally \(intelligence\) or just to your organization | 
| DigitalShadows.Incidents.Type | unknown | The category of incident that has been raised | 
| DigitalShadows.Incidents.Title | unknown | A short but descriptive identifier for the incident | 
| DigitalShadows.Incidents.Review.Created | unknown | The moment in time the review was created | 
| DigitalShadows.Incidents.Review.Status | unknown | Review status | 
| DigitalShadows.Incidents.Review.User | unknown | The user that changed the status/set the note | 
| DigitalShadows.Incidents.SubType | unknown | The sub-category of incident that has been raised, if available | 
| DigitalShadows.Incidents.Severity | unknown | Analyst defined severity based on potential risk to the client | 


#### Command Example
```!ds-get-incident incident_id=99002724```

#### Context Example
```json
{
    "DigitalShadows": {
        "Incidents": {
            "Alerted": null,
            "Description": "Several documents in .docx, .xls, and .ppt format were identified on a publicly accessible some derive on the following IP: 1.2.3.4. \r\n",
            "Id": 99002724,
            "ImpactDescription": "The IP address contained 30 documents relating to the Company at the following paths: \r\n\r\n1.\thxxps://1.2.3.4//man",
            "Internal": false,
            "Mitigation": "As the drives are no longer accessible",
            "Modified": "2020-11-06T00:22:57.753Z",
            "Occurred": "2018-08-23T03:45:57.215Z",
            "Review": {
                "Created": "2019-08-01T13:19:53.522Z",
                "Status": "UNREAD",
                "User": null
            },
            "Scope": "ORGANIZATION",
            "Severity": "MEDIUM",
            "SubType": "UNMARKED_DOCUMENT",
            "Title": "Vendor documents identified on publicly accessible Network Attached Storage drive",
            "Type": "DATA_LEAKAGE"
        }
    }
}
```

#### Human Readable Output

>### Digital Shadows Incidents
> Alerted| Description| Id| ImpactDescription| Internal| Mitigation| Modified| Occurred| Review Created| Review Status| Review User| Scope| Severity| SubType| Title| Type
>---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---
>  | Several documents in .docx, .xls, and .ppt format were identified on a publicly accessible some derive on the following IP: 1.2.3.4.  <br/> | 99002724 | The IP address contained 30 documents relating to the Company at the following paths: <br/><br/>1.	hxxps://1.2.3.4//man | false | As the drives are no longer accessible.| 2020-11-06T00:22:57.753Z | 2018-08-23T03:45:57.215Z | 2019-08-01T13:19:53.522Z | UNREAD |   | ORGANIZATION | MEDIUM | UNMARKED_DOCUMENT | Vendor documents identified on publicly accessible Network Attached Storage drive | DATA_LEAKAGE


### ds-get-incident-reviews
***
Retrieve all review updates for a given incident


#### Base Command

`ds-get-incident-reviews`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Id of the incident to retrieve the review history for. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DigitalShadows.IncidentReviews.Note | unknown | The note at this version \(max length 500 characters\) | 
| DigitalShadows.IncidentReviews.Created | unknown | The moment in time the review was created | 
| DigitalShadows.IncidentReviews.Status | unknown | Review status | 
| DigitalShadows.IncidentReviews.User.Id | unknown | The unique id of the user that changed the status/set the note. | 
| DigitalShadows.IncidentReviews.User.EmailAddress | unknown | The email address of the user that changed the status/set the note. | 
| DigitalShadows.IncidentReviews.User.FullName | unknown | The full name of the user that changed the status/set the note. | 
| DigitalShadows.IncidentReviews.User.Role | unknown | The role of the user that changed the status/set the note. | 
| DigitalShadows.IncidentReviews.User.Status | unknown | The status of the user that changed the status/set the note. | 


#### Command Example
```!ds-get-incident-reviews incident_id=99002724```

#### Context Example
```json
{
    "DigitalShadows": {
        "IncidentReviews": {
            "Created": "2019-08-01T13:19:53.522Z",
            "Note": null,
            "Status": "UNREAD",
            "User": {
                "EmailAddress": null,
                "FullName": null,
                "Id": null,
                "Role": null,
                "Status": null
            },
            "Version": 1
        }
    }
}
```

#### Human Readable Output

>### Digital Shadows Incident Reviews
> Created| Note| Status| User EmailAddress| User FullName| User Id| User Role| User Status| Version
>---|---|---|---|---|---|---|---|---
>2019-08-01T13:19:53.522Z |   | UNREAD |   |   |   |   |   | 1


### ds-snapshot-incident-review
***
Snapshot the review status of an incident


#### Base Command

`ds-snapshot-incident-review`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Id of the incident to apply a review update to. | Required | 
| note | The note at this version (max length 500 characters). | Optional | 
| status | Review status | Optional | 
| version | When submitting, this value can be optionally set to the version of the most recently read review. If the version on the server does not match this value, a 409 conflict will be returned. | Optional | 


#### Context Output

There is no context output for this command.


### ds-find-incidents-filtered
***
Find incidents with filtering options


#### Base Command

`ds-find-incidents-filtered`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| subscribed | If true, the results will also include any subscribed intelligence incidents. | Optional | 
| subscribedOnly | If true, the only results returned will be subscribed intelligence incidents. Must not be set to true with subscribed set to false | Optional | 
| pagination_containingId | Select the page containing the record with this id, if supported. Mutually exclusive with offset. | Optional | 
| pagination_offset | Include results at this offset within the full resultset, where the first result is at position 0 | Optional | 
| pagination_size | Maximum number of results to return per page, can be initially null to be replaced by default later | Optional | 
| sort_direction | The direction of sorting. If not specified, ASCENDING is assumed | Optional | 
| sort_property | The name of the property being sorted on. This normally corresponds to the property name of the result type, but could be a 'virtual property'. | Optional | 
| filter_alerted | Only incidents that have been alerted to the client. | Optional | 
| filter_dateRange | Only return results that were verified/occurred/modified within this date range (inclusive). The field this applies to is controlled by dateRangeField. Supports ISO Periods (eg P1D), intervals (eg 2015-01-01T00:00:00Z/2015-01-31T00:00:00Z) and any one of the constants {TODAY, YESTERDAY, WEEK, LAST_WEEK, MONTH, LAST_MONTH, YEAR, LAST_YEAR}. | Optional | 
| filter_dateRangeField | Determines which date/time field the dateRange will apply to. | Optional | 
| filter_domainName | Only incidents that have this domain, applied if domainSelection is null or CUSTOM | Optional | 
| filter_domainSelection | Determine how domain filtering will be applied. | Optional | 
| filter_identifier | Only return the incident that has this identifier. | Optional | 
| filter_repostedCredentials | Option specific to data breach based incidents to filter out new and reposted breach credentials. ORIGINAL, REPOST | Optional | 
| filter_severities | Only include incidents with these severities, if not specified, all are considered. VERY_HIGH, HIGH, MEDIUM, LOW, VERY_LOW, NONE | Optional | 
| filter_statuses | UNREAD, READ, CLOSED | Optional | 
| filter_types_type | The category of incident that has been raised. | Optional | 
| filter_types_subTypes | The sub-category of incident that has been raised, if available. | Optional | 
| filter_types_content_severity | Analyst defined severity based on potential risk to the client. | Optional | 
| filter_tagOperator | Whether multiple tags should be logically applied as AND/OR with the resultset | Optional | 
| filter_withContentRemoved | Include incidents for which the content of the incident has been removed form the source. | Optional | 
| filter_withTakedown | Include incidents on which one or more takedown requests have been generated. | Optional | 
| filter_withoutContentRemoved | Include incidents for which the content of the incident has not been removed form the source. | Optional | 
| filter_withoutTakedown | Include incidents on which a takedown request has not been generated. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DigitalShadows.Incidents.Alerted | unknown | The moment this incident was brought to the attention of the client | 
| DigitalShadows.Incidents.Description | unknown | Plain text description of this incident | 
| DigitalShadows.Incidents.Id | unknown | Identifier for this incident, unique in combination with the scope | 
| DigitalShadows.Incidents.Internal | unknown | Will be true if domain belongs to your organization \(as defined by the assets\), false otherwis | 
| DigitalShadows.Incidents.Mitigation | unknown | Information about what can be done to mitigate the effect of the problem | 
| DigitalShadows.Incidents.Modified | unknown | When was this incident last modified | 
| DigitalShadows.Incidents.Occurred | unknown | Best effort to establish when the incident occurred | 
| DigitalShadows.Incidents.Published | unknown | When was this incident originally published | 
| DigitalShadows.Incidents.RestrictedContent | unknown | Identifies this incident as potentially containing questionable content. If this is true images will be restricted | 
| DigitalShadows.Incidents.Scope | unknown | Identifies whether this incident applies globally \(intelligence\) or just to your organization | 
| DigitalShadows.Incidents.Severity | unknown | Analyst defined severity based on potential risk to the client | 
| DigitalShadows.Incidents.SubType | unknown | The sub-category of incident that has been raised, if available | 
| DigitalShadows.Incidents.Verified | unknown | The moment when the incident was verified | 
| DigitalShadows.Incidents.Type | unknown | The category of incident that has been raised | 
| DigitalShadows.Incidents.Version | unknown | Each time an update occurs, this version number is incremented | 
| DigitalShadows.Incidents.Review.Created | unknown | The date the review state for this incident was created | 
| DigitalShadows.Incidents.Review.Status | unknown | The status of the review state for this incident | 
| DigitalShadows.Incidents.Review.User.id | unknown | The user that create the review state for this incident | 
| DigitalShadows.Incidents.Review.User.fullName | unknown | The full name of the user that created review state for this incident | 


#### Command Example
```!ds-find-incidents-filtered pagination_size=3```

#### Context Example
```json
{
    "DigitalShadows": {
        "Incidents": {
            "Alerted": null,
            "Description": "Several documents in .docx, .xls, and .ppt format were identified on a publicly accessible some derive on the following IP: 1.2.3.4.",
            "Id": 99002724,
            "Internal": null,
            "Mitigation": "As the drives are no longer accessible.",
            "Modified": "2020-11-05T00:33:48.344Z",
            "Occurred": "2018-08-23T03:45:57.215Z",
            "Published": "2020-11-04T23:59:59.999Z",
            "RecordCount": null,
            "RestrictedContent": null,
            "Review": {
                "Created": "2019-08-01T13:19:53.522Z",
                "Status": "UNREAD",
                "User": null
            },
            "Scope": "ORGANIZATION",
            "Score": 0,
            "Severity": "MEDIUM",
            "SubType": {
                "Error": "You must provide the query to use"
            },
            "Title": "Vendor documents identified on publicly accessible Network Attached Storage drive",
            "Type": "DATA_LEAKAGE",
            "Verified": {
                "Error": "You must provide the query to use"
            },
            "Version": {
                "Error": "You must provide the query to use"
            }
        }
    }
}
```

#### Human Readable Output

>### Digital Shadows Incidents
> Alerted| Description| Id| Internal| Mitigation| Modified| Occurred| Published| RecordCount| RestrictedContent| Review Created| Review Status| Review User| Scope| Score| Severity| SubType| Title| Type| Verified| Version
>---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---
>  | Several documents in .docx, .xls, and .ppt format were identified on a publicly accessible some derive on the following IP: 1.2.3.4. | 99002724 |   | As the drives are no longer accessible. | 2020-11-05T00:33:48.344Z | 2018-08-23T03:45:57.215Z | 2020-11-04T23:59:59.999Z |   |   | 2019-08-01T13:19:53.522Z | UNREAD |   | ORGANIZATION | 0 | MEDIUM | {"Error":"You must provide the query to use"} | Vendor documents identified on publicly accessible Network Attached Storage drive | DATA_LEAKAGE | {"Error":"You must provide the query to use"} | {"Error":"You must provide the query to use"}


### ds-get-incidents-summary
***
Aggregated summary of incident information used to generate reports/statistics


#### Base Command

`ds-get-incidents-summary`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter_domainName | Only incidents that have this domain, applied if domainSelection is null or CUSTOM | Optional | 
| filter_dateRangeField | Determines which date/time field the dateRange will apply to. | Optional | 
| filter_identifier | Only return the incident that has this identifier. | Optional | 
| filter_dateRange | Only return results that were verified/occurred/modified within this date range (inclusive). The field this applies to is controlled by dateRangeField. Supports ISO Periods (eg P1D), intervals (eg 2015-01-01T00:00:00Z/2015-01-31T00:00:00Z) and any one of the constants {TODAY, YESTERDAY, WEEK, LAST_WEEK, MONTH, LAST_MONTH, YEAR, LAST_YEAR}. | Optional | 
| groupByKey | Determines which incident property will be grouped on. Mutually exclusive with groupByKeys | Optional | 
| sort_direction | The direction of sorting. If not specified, ASCENDING is assumed | Optional | 
| sort_property | The name of the property being sorted on. This normally corresponds to the property name of the result type, but could be a 'virtual property'. | Optional | 
| pagination_containingId | Select the page containing the record with this id, if supported. Mutually exclusive with offset. | Optional | 
| pagination_offset | Include results at this offset within the full resultset, where the first result is at position 0 | Optional | 
| pagination_size | Maximum number of results to return per page, can be initially null to be replaced by default later | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!ds-get-incidents-summary pagination_size=2```


#### Human Readable Output

>{"keySet":[null],"ranges":[{"groupedIncidentCounts":[{"count":25}],"rangeEnd":"2020-11-05T17:37:26.533Z","rangeStart":"2020-11-01T00:00:00.000Z","total":25}]}

### ds-get-apt-report
***
Retrieve details of the specified APT report


#### Base Command

`ds-get-apt-report`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | The unique identifier assigned to a given APT report (UUID based). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DigitalShadows.APTReports.Id | unknown | Internal identifier for uniquely identifying this report | 
| DigitalShadows.APTReports.Name | unknown | Name assigned to this report for ease of identification | 
| DigitalShadows.APTReports.Published | unknown | The date the report became available | 
| DigitalShadows.APTReports.Report.Id | unknown | The ID of the report resource allowing it to be downloaded | 
| DigitalShadows.APTReports.Report.Link | unknown | The link of the report resource allowing it to be downloaded | 
| DigitalShadows.APTReports.Preview.Id | unknown | ID of a preview image of the frontpage of the report, if available | 
| DigitalShadows.APTReports.Preview.Link | unknown | A fully qualified link URI for preview image of the frontpage of the report, if available | 


### ds-get-intelligence-incident
***
Retrieve an intelligence incident by its id


#### Base Command

`ds-get-intelligence-incident`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The id of the intelligence incident to retrieve | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DigitalShadows.IntelligenceIncidents.Description | unknown | Plain text description of this incident. | 
| DigitalShadows.IntelligenceIncidents.Id | unknown | Identifier for this incident, unique in combination with the scope | 
| DigitalShadows.IntelligenceIncidents.IndicatorOfCompromiseCount | unknown | Count of IOCs that can be retrieved via /api/incidents/\{id\}/iocs endpoint | 
| DigitalShadows.IntelligenceIncidents.Internal | unknown | Will be true if domain belongs to your organization \(as defined by the assets\), false otherwise | 
| DigitalShadows.IntelligenceIncidents.LinkedContentIncidents | unknown | Other incidents that appear to be based on the same content as this incident. Each incident record will normally only contain the id and the scope it applies to. Could also include more details depending on the context it is called in. | 
| DigitalShadows.IntelligenceIncidents.Modified | unknown | When was this incident last modified | 
| DigitalShadows.IntelligenceIncidents.Occurred | unknown | Best effort to establish when the incident occurred | 
| DigitalShadows.IntelligenceIncidents.Published | unknown | When was this incident originally published | 
| DigitalShadows.IntelligenceIncidents.RelatedIncidentId | unknown | If an incident specific to your organization exists for this intelligence incident, it will be included here. | 
| DigitalShadows.IntelligenceIncidents.RestrictedContent | unknown | Identifies this incident as potentially containing questionable content. If this is true images will be restricted. | 
| DigitalShadows.IntelligenceIncidents.Scope | unknown | Identifies whether this incident applies globally \(intelligence\) or just to your organization. | 
| DigitalShadows.IntelligenceIncidents.Severity | unknown | Analyst defined severity based on potential risk to the client | 
| DigitalShadows.IntelligenceIncidents.SubType | unknown | The sub-category of incident that has been raised, if available | 
| DigitalShadows.IntelligenceIncidents.Title | unknown | A short but descriptive identifier for the incident | 
| DigitalShadows.IntelligenceIncidents.Type | unknown | The category of incident that has been raised | 
| DigitalShadows.IntelligenceIncidents.Verified | unknown | The moment when the incident was verified. | 
| DigitalShadows.IntelligenceIncidents.Version | unknown | Each time an update occurs, this version number is incremented | 


#### Command Example
```!ds-get-intelligence-incident incident_id=6470614```

#### Context Example
```json
{
    "DigitalShadows": {
        "IntelligenceIncidents": {
            "Description": "Summary: some event in the past",
            "Id": 6470614,
            "IndicatorOfCompromiseCount": 0,
            "Internal": false,
            "LinkedContentIncidents": null,
            "Modified": "2018-08-30T07:18:22.566Z",
            "Occurred": "2016-02-08T10:55:00.000Z",
            "Published": "2016-02-08T12:22:03.203Z",
            "RelatedIncidentId": null,
            "RestrictedContent": false,
            "Scope": "GLOBAL",
            "Severity": "LOW",
            "SubType": null,
            "Title": "08 Feb 2016 protest update",
            "Type": "CYBER_THREAT",
            "Verified": "2016-02-08T11:22:48.539Z",
            "Version": 12
        }
    }
}
```

#### Human Readable Output

>### Digital Shadows Intelligence Incident
> Description| Id| IndicatorOfCompromiseCount| Internal| LinkedContentIncidents| Modified| Occurred| Published| RelatedIncidentId| RestrictedContent| Scope| Severity| SubType| Title| Type| Verified| Version
>---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---
>Summary: some event in the past | 6470614 | 0 | false |   | 2018-08-30T07:18:22.566Z | 2016-02-08T10:55:00.000Z | 2016-02-08T12:22:03.203Z |   | false | GLOBAL | LOW |   | 08 Feb 2016 protest update | CYBER_THREAT | 2016-02-08T11:22:48.539Z | 12


### ds-get-intelligence-incident-iocs
***
Retrieve the indicatorsOfCompromise for this intel incident


#### Base Command

`ds-get-intelligence-incident-iocs`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The intelligence incident identifier | Required | 
| visible | List of values to control the visibility of elements. If a value is present then the correspinding element should be displayed | Optional | 
| sort_direction | The direction of sorting. If not specified, ASCENDING is assumed | Optional | 
| sort_property | The name of the property being sorted on. This normally corresponds to the property name of the result type, but could be a 'virtual property'. | Optional | 
| pagination_containingId | Select the page containing the record with this id, if supported. Mutually exclusive with offset. | Optional | 
| pagination_offset | Include results at this offset within the full resultset, where the first result is at position 0 | Optional | 
| pagination_size | Maximum number of results to return per page, can be initially null to be replaced by default later | Optional | 
| filter_value | The filter that will narrow the results based on one or more criteria | Optional | 
| filter_types | List of types to filter by. Possible values are IP,MD5,SHA1,SHA256,URL,CVE,EMAIL,HOST,REGISTRY,FILEPATH,FILENAME | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DigitalShadows.IntelligenceIncidentsIOCs.Id | unknown | Internal identifier for uniquely identifying this IOC | 
| DigitalShadows.IntelligenceIncidentsIOCs.IntelIncident.Id | unknown | If this IOC is associated with an intel incident | 
| DigitalShadows.IntelligenceIncidentsIOCs.IntelIncident.Scope | unknown | If this IOC is associated with an intel incident | 
| DigitalShadows.IntelligenceIncidentsIOCs.Type | unknown | Identifies the type of incidicator that also determines how it is encoded into a string | 
| DigitalShadows.IntelligenceIncidentsIOCs.Value | unknown | The value of this indicator, encoded according to its type. For example hashes are base16 encoded. | 
| DigitalShadows.IntelligenceIncidentsIOCs.Source | unknown | A comment provided by the analysts as to where this IOC came from. | 
| DigitalShadows.IntelligenceIncidentsIOCs.LastUpdated | unknown | When this record last changed | 
| DigitalShadows.IntelligenceIncidentsIOCs.AptReport.Id | unknown | If this IOC is associated with an APT report | 


#### Command Example
``` ```

#### Human Readable Output



### ds-find-intelligence-incidents
***
Find intelligence incidents


#### Base Command

`ds-find-intelligence-incidents`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter_dateRange | Only return results that were verified/occurred/modified within this date range (inclusive). The field this applies to is controlled by dateRangeField. Supports ISO Periods (eg P1D), intervals (eg 2015-01-01T00:00:00Z/2015-01-31T00:00:00Z) and any one of the constants {TODAY, YESTERDAY, WEEK, LAST_WEEK, MONTH, LAST_MONTH, YEAR, LAST_YEAR}. | Optional | 
| filter_dateRangeField | Determines which date/time field the dateRange will apply to. | Optional | 
| filter_domainName | Only incidents that have this domain, applied if domainSelection is null or CUSTOM | Optional | 
| filter_domainSelection | Determine how domain filtering will be applied. | Optional | 
| filter_identifier | Only return the incident that has this identifier. | Optional | 
| filter_severities | Only include SSL/certificate infrastructure incidents with these severities. String values from VERY_HIGH, HIGH, MEDIUM, LOW, VERY_LOW, NONE | Optional | 
| filter_tagOperator | Whether multiple tags should be logically applied as AND/OR with the resultset | Optional | 
| filter_tags_id | Limit to incidents that have these tags ids only. | Optional | 
| filter_threatRecordIds | Restrict intel incidents to those tagged with one or more of these threat records. | Optional | 
| filter_threatTypes_type | Restrict intel incidents to those associated with threats of these types:ACTOR,CAMPAIGN,EVENT,TOOL,SPECIFIC_TTP,LOCATION | Optional | 
| filter_threatTypes | The type to match to. Will match to any incident with this type unless subTypes is not empty, in which case only incident matches based on the sub-type will be considered. | Optional | 
| filter_threatSubTypes | List of pecific sub type(s) to match to. String values from BRAND_MISUSE, COMPANY_THREAT, CORPORATE_INFORMATION, CREDENTIAL_COMPROMISE, CUSTOMER_DETAILS, CVE, DEFAMATION, DOMAIN_CERTIFICATE_ISSUE, EMPLOYEE_THREAT, EXPOSED_PORT, INTELLECTUAL_PROPERTY, INTERNALLY_MARKED_DOCUMENT, LEGACY_MARKED_DOCUMENT, MOBILE_APPLICATION, NEGATIVE_PUBLICITY, PERSONAL_INFORMATION, PHISHING_ATTEMPT, PROTECTIVELY_MARKED_DOCUMENT, SPOOF_PROFILE, TECHNICAL_INFORMATION,TECHNICAL_LEAKAGE, UNMARKED_DOCUMENT | Optional | 
| pagination_containingId | Select the page containing the record with this id, if supported. Mutually exclusive with offset. | Optional | 
| pagination_offset | Include results at this offset within the full resultset, where the first result is at position 0 | Optional | 
| pagination_size | Maximum number of results to return per page, can be initially null to be replaced by default later | Optional | 
| sort_direction | The direction of sorting. If not specified, ASCENDING is assumed | Optional | 
| sort_property | The name of the property being sorted on. This normally corresponds to the property name of the result type, but could be a 'virtual property'. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DigitalShadows.IntelligenceIncidents.Description | unknown | Plain text description of this incident. | 
| DigitalShadows.IntelligenceIncidents.Id | unknown | Identifier for this incident, unique in combination with the scope | 
| DigitalShadows.IntelligenceIncidents.IndicatorOfCompromiseCount | unknown | Count of IOCs that can be retrieved via /api/incidents/\{id\}/iocs endpoint | 
| DigitalShadows.IntelligenceIncidents.Internal | unknown | Will be true if domain belongs to your organization \(as defined by the assets\), false otherwise | 
| DigitalShadows.IntelligenceIncidents.LinkedContentIncidents | unknown | Other incidents that appear to be based on the same content as this incident. Each incident record will normally only contain the id and the scope it applies to. Could also include more details depending on the context it is called in. | 
| DigitalShadows.IntelligenceIncidents.Modified | unknown | When was this incident last modified | 
| DigitalShadows.IntelligenceIncidents.Occurred | unknown | Best effort to establish when the incident occurred | 
| DigitalShadows.IntelligenceIncidents.Published | unknown | When was this incident originally published | 
| DigitalShadows.IntelligenceIncidents.RelatedIncidentId | unknown | If an incident specific to your organization exists for this intelligence incident, it will be included here. | 
| DigitalShadows.IntelligenceIncidents.RestrictedContent | unknown | Identifies this incident as potentially containing questionable content. If this is true images will be restricted. | 
| DigitalShadows.IntelligenceIncidents.Scope | unknown | Identifies whether this incident applies globally \(intelligence\) or just to your organization. | 
| DigitalShadows.IntelligenceIncidents.Severity | unknown | Analyst defined severity based on potential risk to the client | 
| DigitalShadows.IntelligenceIncidents.SubType | unknown | The sub-category of incident that has been raised, if available | 
| DigitalShadows.IntelligenceIncidents.Title | unknown | A short but descriptive identifier for the incident | 
| DigitalShadows.IntelligenceIncidents.Type | unknown | The category of incident that has been raised | 
| DigitalShadows.IntelligenceIncidents.Verified | unknown | The moment when the incident was verified. | 
| DigitalShadows.IntelligenceIncidents.Version | unknown | Each time an update occurs, this version number is incremented | 


#### Command Example
```!ds-find-intelligence-incidents pagination_size=2```

#### Context Example
```json
{
    "DigitalShadows": {
        "IntelligenceIncidents": [
            {
                "Description": "A new post was added to Happy Blog.",
                "Id": 65624604,
                "IndicatorOfCompromiseCount": 0,
                "Internal": false,
                "LinkedContentIncidents": null,
                "Modified": "2020-11-05T15:53:33.166Z",
                "Occurred": "2020-11-05T05:48:42.588Z",
                "Published": "2020-11-05T15:53:33.161Z",
                "RelatedIncidentId": null,
                "RestrictedContent": false,
                "Scope": "GLOBAL",
                "Severity": "LOW",
                "SubType": null,
                "Title": "Tipper: Richardson Sales Performance named on Happy Blog ",
                "Type": "CYBER_THREAT",
                "Verified": "2020-11-05T14:01:48.656Z",
                "Version": 7
            },
            {
                "Description": "A new post was added to Happy Blog.",
                "Id": 65604506,
                "IndicatorOfCompromiseCount": 0,
                "Internal": false,
                "LinkedContentIncidents": null,
                "Modified": "2020-11-05T15:47:36.590Z",
                "Occurred": "2020-11-04T21:48:04.784Z",
                "Published": "2020-11-05T15:47:36.582Z",
                "RelatedIncidentId": null,
                "RestrictedContent": false,
                "Scope": "GLOBAL",
                "Severity": "LOW",
                "SubType": null,
                "Title": "Tipper: New Jersey Dental Hygienists' Association",
                "Type": "CYBER_THREAT",
                "Verified": "2020-11-05T14:01:48.656Z",
                "Version": 7
            }
        ]
    }
}
```

#### Human Readable Output

>### Digital Shadows Intelligence Incidents
> Description| Id| IndicatorOfCompromiseCount| Internal| LinkedContentIncidents| Modified| Occurred| Published| RelatedIncidentId| RestrictedContent| Scope| Severity| SubType| Title| Type| Verified| Version
>---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---
>A new post was added to Happy Blog. | 65624604 | 0 | false |   | 2020-11-05T15:53:33.166Z | 2020-11-05T05:48:42.588Z | 2020-11-05T15:53:33.161Z |   | false | GLOBAL | LOW |   | Tipper: Richardson Sales Performance named on Happy Blog  | CYBER_THREAT | 2020-11-05T14:01:48.656Z | 7
>A new post was added to Happy Blog. | 65604506 | 0 | false |   | 2020-11-05T15:47:36.590Z | 2020-11-04T21:48:04.784Z | 2020-11-05T15:47:36.582Z |   | false | GLOBAL | LOW |   | Tipper: New Jersey Dental Hygienists' Association | CYBER_THREAT | 2020-11-05T14:01:48.656Z | 7


### ds-find-intelligence-incidents-regional
***
Incidents grouped by the target country over a given time range


#### Base Command

`ds-find-intelligence-incidents-regional`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| threat_id | Threat ID | Optional | 
| countryTag_created | When was this tag created. | Optional | 
| countryTag_description | Description text for this tag. | Optional | 
| countryTag_id | Unique integer identifier for this tag | Optional | 
| countryTag_name | The name of this tag. Is unique in combination with the type | Optional | 
| countryTag_parent_id | Parent id of the tag | Optional | 
| countryTag_threat_id | Unique integer identifier (among threats). | Optional | 
| countryTag_threat_type | The type of profile being represented. | Optional | 
| countryTag_type | The type of this tag. The name of tags with the same type must be unique. | Optional | 
| filter_dateRange | Determines the interval the incidents must have occurred within to be included. Supports ISO Periods (eg P1D), intervals (eg 2015-01-01T00:00:00Z/2015-01-31T00:00:00Z) and any one of the constants {TODAY, YESTERDAY, WEEK, LAST_WEEK, MONTH, LAST_MONTH, YEAR, LAST_YEAR}. | Optional | 
| filter_periodRelativeTo | Optional timestamp that will be used as the end date for a period based dateRange. If not specified, then the end of the current day (based on the requesting user's timezone) will be used. | Optional | 
| filter_tagType | What types of tags should be considered. Should be one of SOURCE_GEOGRAPHY or TARGET_GEOGRAPHY (the default) | Optional | 
| regionTag_created | When was this tag created. | Optional | 
| regionTag_description | Description text for this tag. | Optional | 
| regionTag_id | Unique integer identifier for this tag | Optional | 
| regionTag_name | The name of this tag. Is unique in combination with the type | Optional | 
| regionTag_parent_id | Parent id of the tag | Optional | 
| regionTag_threat_id | Unique integer identifier (among threats). | Optional | 
| regionTag_threat_type | The type of profile being represented. | Optional | 
| regionTag_type | The type of this tag. The name of tags with the same type must be unique. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DigitalShadows.IntelligenceIncidentsRegional.CountryTag.Id | unknown | The ID of the country these incidents are attributed to | 
| DigitalShadows.IntelligenceIncidentsRegional.CountryTag.Name | unknown | The country name these incidents are attributed to | 
| DigitalShadows.IntelligenceIncidentsRegional.CountryTag.ParentId | unknown | The parent ID of the country these incidents are attributed to | 
| DigitalShadows.IntelligenceIncidentsRegional.CountryTag.ThreatId | unknown | The threat id of the country tag these incidents are attributed to | 
| DigitalShadows.IntelligenceIncidentsRegional.CountryTag.Type | unknown | The country tag type these incidents are attributed to | 
| DigitalShadows.IntelligenceIncidentsRegional.IncidentIds | unknown | The list of intelligence incidents | 


### ds-get-intelligence-threat
***
Retrieve a specific item of intelligence by its id


#### Base Command

`ds-get-intelligence-threat`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| threat_id | The id of the intelligence threat to retrieve. | Required | 
| opt | Options to include additional relevant data with the request | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DigitalShadows.IntelligenceThreats.ActivityLevel | unknown | Level of activity, based on last active | 
| DigitalShadows.IntelligenceThreats.DetailLevel | unknown | Determines how detailed the record is | 
| DigitalShadows.IntelligenceThreats.EndDate | unknown | The end date of the period this was/is active | 
| DigitalShadows.IntelligenceThreats.Id | unknown | Unique integer identifier \(among threats\) | 
| DigitalShadows.IntelligenceThreats.ImageId | unknown | The unique identifier for an image of the threat, if available. The actual image can be retrieved by requesting /api/resources/\{id\} \(replacing \{id\} with the value of this property\). | 
| DigitalShadows.IntelligenceThreats.ImageThumbnailId | unknown | The unique identifier for a thumbnail of the image, if available. The image can be retrieved by requesting /api/thumbnails/\{id\} \(replacing \{id\} with the value of this property\) | 
| DigitalShadows.IntelligenceThreats.IndicatorOfCompromiseCount | unknown | Count of IOCs | 
| DigitalShadows.IntelligenceThreats.LastActive | unknown | The date of last activity \(last incident\) | 
| DigitalShadows.IntelligenceThreats.Recurring | unknown | Will this become active again in future? | 
| DigitalShadows.IntelligenceThreats.StartDate | unknown | The start date of the period this was/is active | 
| DigitalShadows.IntelligenceThreats.Type | unknown | The type of profile being represented | 
| DigitalShadows.IntelligenceThreats.Tags.ActorTypeTags | unknown | Tags for the type of actor | 
| DigitalShadows.IntelligenceThreats.AnnouncementIncidentIDs | unknown | List of public declarations made \(incidents\) | 
| DigitalShadows.IntelligenceThreats.AptReportIDs | unknown | APT reports associated with this threat. Each entry can be resolved via the /api/apt-report/\{id\} endpoint. | 
| DigitalShadows.IntelligenceThreats.Tags.AssociatedActorTags | unknown | Actors related to this threat \(if any\) | 
| DigitalShadows.IntelligenceThreats.Tags.AssociatedCampaignTags | unknown | Campaigns related to this threat \(if any\) | 
| DigitalShadows.IntelligenceThreats.AssociatedEventIDs | unknown | Events associated with this threat \(if any\) | 
| DigitalShadows.IntelligenceThreats.AttackEvidenceIncidentIDs | unknown | List of damage caused incidents | 
| DigitalShadows.IntelligenceThreats.Tags.ImpactEffectTags | unknown | What impact did it have | 
| DigitalShadows.IntelligenceThreats.Tags.IntendedEffectTags | unknown | What the threat intended to happen | 
| DigitalShadows.IntelligenceThreats.LatestIncidentID | unknown | The latest incident attributed to this threat | 
| DigitalShadows.IntelligenceThreats.Tags.MotivationTags | unknown | Tags that define what motivates the threat | 
| DigitalShadows.IntelligenceThreats.Tags.OverviewTags | unknown | Tags that will appear in the overview. Only one per primary type | 
| DigitalShadows.IntelligenceThreats.Tags.PrimaryLanguageTags | unknown | Tags that identify the primary languages used | 
| DigitalShadows.IntelligenceThreats.ThreatLevel | unknown | Information about the level of threat, for example low or high | 


#### Command Example
```!ds-get-intelligence-threat threat_id=2351```

#### Context Example
```json
{
    "DigitalShadows": {
        "IntelligenceThreats": {
            "ActivityLevel": "INACTIVE",
            "AnnouncementIncidentIDs": null,
            "AptReportIDs": null,
            "AssociatedEventIDs": null,
            "AttackEvidenceIncidentIDs": null,
            "EndDate": null,
            "Id": 2351,
            "ImageId": "id",
            "ImageThumbnailId": "id",
            "IndicatorOfCompromiseCount": 0,
            "LastActive": "2016-07-20T22:00:00.000Z",
            "LatestIncident": null,
            "LatestIncidentID": null,
            "Recurring": null,
            "StartDate": null,
            "Tags": {
                "ActorTypeTags": [
                    {
                        "id": 1107,
                        "name": "Hacker - Black hat",
                        "type": "ACTOR_TYPE"
                    },
                ],
                "AssociatedActorTags": [
                    {
                        "id": 3208,
                        "name": "Peace of Mind",
                        "type": "ACTOR"
                    },
                ],
                "AssociatedCampaignTags": [],
                "ImpactEffectTags": [
                    {
                        "id": 424,
                        "name": "Data Breach or Compromise",
                        "type": "IMPACT_EFFECTS"
                    },
                    {
                        "id": 431,
                        "name": "Unintended Access",
                        "type": "IMPACT_EFFECTS"
                    }
                ],
                "IntendedEffectTags": [
                    {
                        "id": 418,
                        "name": "Unauthorised Access",
                        "type": "INTENDED_EFFECTS"
                    },
                    {
                        "id": 412,
                        "name": " Exposure",
                        "type": "INTENDED_EFFECTS"
                    }
                ],
                "MotivationTags": [
                    {
                        "id": 434,
                        "name": "Ideological - Anti-Corruption",
                        "type": "MOTIVATION"
                    },
                    {
                        "id": 440,
                        "name": "Ideological - Security Awareness",
                        "type": "MOTIVATION"
                    }
                ],
                "OverviewTags": [
                    {
                        "id": 1874,
                        "name": "Data Leakage",
                        "parent": {
                            "id": 2684
                        },
                        "type": "GENERAL_TTP"
                    },
                    {
                        "id": 1088,
                        "name": "Government",
                        "type": "TARGET_SECTORS"
                    }
                ],
                "PrimaryLanguageTags": [
                    {
                        "id": 467,
                        "name": "English",
                        "type": "LANGUAGE"
                    },
                    {
                        "id": 526,
                        "name": "Spanish",
                        "type": "LANGUAGE"
                    }
                ],
                "PrimaryTag": {
                    "id": 3177,
                    "name": "CthulhuSec",
                    "type": "ACTOR"
                },
                "SourceGeographyTags": []
            },
            "ThreatLevel": "LOW",
            "Type": "ACTOR"
        }
    }
}
```

#### Human Readable Output

>### Digital Shadows Intelligence Threat
> ActivityLevel| AnnouncementIncidentIDs| AptReportIDs| AssociatedEventIDs| AttackEvidenceIncidentIDs| EndDate| Id| ImageId| ImageThumbnailId| IndicatorOfCompromiseCount| LastActive| LatestIncident| LatestIncidentID| Recurring| StartDate| ThreatLevel| Type
>---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---
>INACTIVE |   |   |   |   |   | 2351 | id | id | 0 | 2016-07-20T22:00:00.000Z |   |   |   |   | LOW | ACTOR


### ds-get-intelligence-threat-iocs
***
Retrieve the indicatorsOfCompromise for a threat record


#### Base Command

`ds-get-intelligence-threat-iocs`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| threat_id | The intelligence threat identifier | Required | 
| filter_types | List of types to filter by. Possible values are IP,MD5,SHA1,SHA256,URL,CVE,EMAIL,HOST,REGISTRY,FILEPATH,FILENAME | Optional | 
| filter_value | Value to filter by | Optional | 
| visible | List of values to control the visibility of elements. If a value is present then the correspinding element should be displayed | Optional | 
| sort_direction | The direction of sorting. If not specified, ASCENDING is assumed | Optional | 
| sort_property | The name of the property being sorted on. This normally corresponds to the property name of the result type, but could be a 'virtual property'. | Optional | 
| pagination_containingId | Select the page containing the record with this id, if supported. Mutually exclusive with offset. | Optional | 
| pagination_offset | Include results at this offset within the full resultset, where the first result is at position 0 | Optional | 
| pagination_size | Maximum number of results to return per page, can be initially null to be replaced by default later | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DigitalShadows.IntelligenceThreatIOCs.AptReportId | unknown | If this IOC is associated with an APT report | 
| DigitalShadows.IntelligenceThreatIOCs.Id | unknown | Internal identifier for uniquely identifying this IOC | 
| DigitalShadows.IntelligenceThreatIOCs.IntelIncidentId | unknown | If this IOC is associated with an intel incident | 
| DigitalShadows.IntelligenceThreatIOCs.LastUpdated | unknown | When this record last changed | 
| DigitalShadows.IntelligenceThreatIOCs.Source | unknown | A comment provided by the analysts as to where this IOC came from | 
| DigitalShadows.IntelligenceThreatIOCs.Type | unknown | Identifies the type of incidicator that also determines how it is encoded into a string | 
| DigitalShadows.IntelligenceThreatIOCs.Value | unknown | The value of this indicator, encoded according to its type. For example hashes are base16 encoded. | 


#### Command Example
``` ```

#### Human Readable Output



### ds-get-intelligence-threat-activity
***
Threat activity based on the number of intelligence incidents over a given period of time.


#### Base Command

`ds-get-intelligence-threat-activity`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| customPrimaryTags_id | Instead of most active, specify the ids of threat primary tags to retrieve activity for | Optional | 
| includeIncidents | Should basic incident information be included with the activity for each tag. | Optional | 
| maximumIncidentsPerTag | Upper limit on the number of incidents to include for each threat. | Optional | 
| mostActiveForTypes | Fetch the top presetPerTypeCount most active threats for each type. Possible values:ACTOR,CAMPAIGN,EVENT,TOOL,SPECIFIC_TTP,LOCATION | Optional | 
| mostActiveLimit | How many threats to retrieve activity for per threat type. Only applies when mostActiveForTypes is not null. If not specified, 10 is assumed. | Optional | 
| segmentCount | Number of time segments to aggregrate the incidents into. | Optional | 
| filter_dateRange | Return activity that occurred in this date range. Supports ISO Periods (eg P1D), intervals (eg 2015-01-01T00:00:00Z/2015-01-31T00:00:00Z) and any one of the constants {TODAY, YESTERDAY, WEEK, LAST_WEEK, MONTH, LAST_MONTH, YEAR, LAST_YEAR}. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!ds-get-intelligence-threat-activity threat_id=2351 filter_dateRange=2016-08-16T19:55:00.000Z/2016-09-16T19:55:00.000Z```


#### Human Readable Output

>{"tagActivities":[{"counts":[{"count":0,"key":"2016-09-13T19:55:00.001Z/2016-09-16T19:55:00.000Z"},{"count":1,"key":"2016-09-10T19:55:00.001Z/2016-09-13T19:55:00.000Z"},{"count":1,"key":"2016-09-07T19:55:00.001Z/2016-09-10T19:55:00.000Z"},{"count":4,"key":"2016-09-04T19:55:00.001Z/2016-09-07T19:55:00.000Z"},{"count":0,"key":"2016-09-01T19:55:00.001Z/2016-09-04T19:55:00.000Z"},{"count":0,"key":"2016-08-29T19:55:00.001Z/2016-09-01T19:55:00.000Z"},{"count":0,"key":"2016-08-26T19:55:00.001Z/2016-08-29T19:55:00.000Z"},{"count":0,"key":"2016-08-23T19:55:00.001Z/2016-08-26T19:55:00.000Z"},{"count":0,"key":"2016-08-20T19:55:00.001Z/2016-08-23T19:55:00.000Z"},{"count":0,"key":"2016-08-17T19:55:00.001Z/2016-08-20T19:55:00.000Z"},{"count":0,"key":"2016-08-16T19:55:00.000Z/2016-08-17T19:55:00.000Z"}],"from":"2016-08-16T19:55:00.000Z","incidents":[{"id":11303017,"scope":"GLOBAL"},{"id":11300637,"scope":"GLOBAL"},{"id":11212704,"scope":"GLOBAL"},{"id":11187135,"scope":"GLOBAL"},{"id":11187153,"scope":"GLOBAL"},{"id":11186833,"scope":"GLOBAL"}],"tag":{"id":3065,"name":"The Real Deal","threat":{"activityLevel":"INACTIVE","closedSource":false,"id":2144,"threatLevel":{"type":"LOW"},"type":"LOCATION"}},"until":"2016-09-16T19:55:00.000Z"},{"counts":[{"count":0,"key":"2016-09-13T19:55:00.001Z/2016-09-16T19:55:00.000Z"},{"count":0,"key":"2016-09-10T19:55:00.001Z/2016-09-13T19:55:00.000Z"},{"count":1,"key":"2016-09-07T19:55:00.001Z/2016-09-10T19:55:00.000Z"},{"count":0,"key":"2016-09-04T19:55:00.001Z/2016-09-07T19:55:00.000Z"},{"count":0,"key":"2016-09-01T19:55:00.001Z/2016-09-04T19:55:00.000Z"},{"count":0,"key":"2016-08-29T19:55:00.001Z/2016-09-01T19:55:00.000Z"},{"count":0,"key":"2016-08-26T19:55:00.001Z/2016-08-29T19:55:00.000Z"},{"count":0,"key":"2016-08-23T19:55:00.001Z/2016-08-26T19:55:00.000Z"},{"count":1,"key":"2016-08-20T19:55:00.001Z/2016-08-23T19:55:00.000Z"},{"count":0,"key":"2016-08-17T19:55:00.001Z/2016-08-20T19:55:00.000Z"},{"count":0,"key":"2016-08-16T19:55:00.000Z/2016-08-17T19:55:00.000Z"}],"from":"2016-08-16T19:55:00.000Z","incidents":[{"id":11258586,"scope":"GLOBAL"},{"id":10924047,"scope":"GLOBAL"}],"tag":{"id":4742,"name":"CrdClub","threat":{"activityLevel":"INACTIVE","closedSource":false,"id":3199,"threatLevel":{"type":"LOW"},"type":"LOCATION"}},"until":"2016-09-16T19:55:00.000Z"},{"counts":[{"count":0,"key":"2016-09-13T19:55:00.001Z/2016-09-16T19:55:00.000Z"},{"count":1,"key":"2016-09-10T19:55:00.001Z/2016-09-13T19:55:00.000Z"},{"count":0,"key":"2016-09-07T19:55:00.001Z/2016-09-10T19:55:00.000Z"},{"count":0,"key":"2016-09-04T19:55:00.001Z/2016-09-07T19:55:00.000Z"},{"count":0,"key":"2016-09-01T19:55:00.001Z/2016-09-04T19:55:00.000Z"},{"count":0,"key":"2016-08-29T19:55:00.001Z/2016-09-01T19:55:00.000Z"},{"count":0,"key":"2016-08-26T19:55:00.001Z/2016-08-29T19:55:00.000Z"},{"count":0,"key":"2016-08-23T19:55:00.001Z/2016-08-26T19:55:00.000Z"},{"count":0,"key":"2016-08-20T19:55:00.001Z/2016-08-23T19:55:00.000Z"},{"count":0,"key":"2016-08-17T19:55:00.001Z/2016-08-20T19:55:00.000Z"},{"count":0,"key":"2016-08-16T19:55:00.000Z/2016-08-17T19:55:00.000Z"}],"from":"2016-08-16T19:55:00.000Z","incidents":[{"id":11303017,"scope":"GLOBAL"}],"tag":{"id":3044,"name":"Hell Forum","threat":{"activityLevel":"INACTIVE","closedSource":false,"id":2122,"threatLevel":{"type":"MEDIUM"},"type":"LOCATION"}},"until":"2016-09-16T19:55:00.000Z"},{"counts":[{"count":0,"key":"2016-09-13T19:55:00.001Z/2016-09-16T19:55:00.000Z"},{"count":0,"key":"2016-09-10T19:55:00.001Z/2016-09-13T19:55:00.000Z"},{"count":1,"key":"2016-09-07T19:55:00.001Z/2016-09-10T19:55:00.000Z"},{"count":0,"key":"2016-09-04T19:55:00.001Z/2016-09-07T19:55:00.000Z"},{"count":0,"key":"2016-09-01T19:55:00.001Z/2016-09-04T19:55:00.000Z"},{"count":0,"key":"2016-08-29T19:55:00.001Z/2016-09-01T19:55:00.000Z"},{"count":0,"key":"2016-08-26T19:55:00.001Z/2016-08-29T19:55:00.000Z"},{"count":0,"key":"2016-08-23T19:55:00.001Z/2016-08-26T19:55:00.000Z"},{"count":0,"key":"2016-08-20T19:55:00.001Z/2016-08-23T19:55:00.000Z"},{"count":0,"key":"2016-08-17T19:55:00.001Z/2016-08-20T19:55:00.000Z"},{"count":0,"key":"2016-08-16T19:55:00.000Z/2016-08-17T19:55:00.000Z"}],"from":"2016-08-16T19:55:00.000Z","incidents":[{"id":11222970,"scope":"GLOBAL"}],"tag":{"id":6966,"name":"Hansa","threat":{"activityLevel":"INACTIVE","closedSource":false,"id":4159,"threatLevel":{"type":"VERY_LOW"},"type":"LOCATION"}},"until":"2016-09-16T19:55:00.000Z"},{"counts":[{"count":0,"key":"2016-09-13T19:55:00.001Z/2016-09-16T19:55:00.000Z"},{"count":0,"key":"2016-09-10T19:55:00.001Z/2016-09-13T19:55:00.000Z"},{"count":0,"key":"2016-09-07T19:55:00.001Z/2016-09-10T19:55:00.000Z"},{"count":0,"key":"2016-09-04T19:55:00.001Z/2016-09-07T19:55:00.000Z"},{"count":0,"key":"2016-09-01T19:55:00.001Z/2016-09-04T19:55:00.000Z"},{"count":0,"key":"2016-08-29T19:55:00.001Z/2016-09-01T19:55:00.000Z"},{"count":0,"key":"2016-08-26T19:55:00.001Z/2016-08-29T19:55:00.000Z"},{"count":0,"key":"2016-08-23T19:55:00.001Z/2016-08-26T19:55:00.000Z"},{"count":1,"key":"2016-08-20T19:55:00.001Z/2016-08-23T19:55:00.000Z"},{"count":0,"key":"2016-08-17T19:55:00.001Z/2016-08-20T19:55:00.000Z"},{"count":0,"key":"2016-08-16T19:55:00.000Z/2016-08-17T19:55:00.000Z"}],"from":"2016-08-16T19:55:00.000Z","incidents":[{"id":10923947,"scope":"GLOBAL"}],"tag":{"id":3048,"name":"AlphaBay","threat":{"activityLevel":"INACTIVE","closedSource":false,"id":2126,"threatLevel":{"type":"VERY_LOW"},"type":"LOCATION"}},"until":"2016-09-16T19:55:00.000Z"},{"counts":[{"count":0,"key":"2016-09-13T19:55:00.001Z/2016-09-16T19:55:00.000Z"},{"count":0,"key":"2016-09-10T19:55:00.001Z/2016-09-13T19:55:00.000Z"},{"count":0,"key":"2016-09-07T19:55:00.001Z/2016-09-10T19:55:00.000Z"},{"count":0,"key":"2016-09-04T19:55:00.001Z/2016-09-07T19:55:00.000Z"},{"count":0,"key":"2016-09-01T19:55:00.001Z/2016-09-04T19:55:00.000Z"},{"count":0,"key":"2016-08-29T19:55:00.001Z/2016-09-01T19:55:00.000Z"},{"count":0,"key":"2016-08-26T19:55:00.001Z/2016-08-29T19:55:00.000Z"},{"count":0,"key":"2016-08-23T19:55:00.001Z/2016-08-26T19:55:00.000Z"},{"count":0,"key":"2016-08-20T19:55:00.001Z/2016-08-23T19:55:00.000Z"},{"count":1,"key":"2016-08-17T19:55:00.001Z/2016-08-20T19:55:00.000Z"},{"count":0,"key":"2016-08-16T19:55:00.000Z/2016-08-17T19:55:00.000Z"}],"from":"2016-08-16T19:55:00.000Z","incidents":[{"id":10847816,"scope":"GLOBAL"}],"tag":{"id":3121,"name":"DownThem","threat":{"activityLevel":"INACTIVE","closedSource":false,"id":2275,"threatLevel":{"type":"LOW"},"type":"LOCATION"}},"until":"2016-09-16T19:55:00.000Z"}],"threatType":"LOCATION","timeSpanDays":31}

### ds-find-intelligence-threats
***
Find intelligence threat records


#### Base Command

`ds-find-intelligence-threats`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter_dateRange | Only return results that were last active within this date range (inclusive). Supports ISO Periods (eg P1D), intervals (eg 2015-01-01T00:00:00Z/2015-01-31T00:00:00Z) and any one of the constants {TODAY, YESTERDAY, WEEK, LAST_WEEK, MONTH, LAST_MONTH, YEAR, LAST_YEAR}. | Optional | 
| filter_dateRangeField | Determines which date/time field the dateRange will apply to. | Optional | 
| filter_identifiers | List of identifiers. Only return threat profiles with these identifiers | Optional | 
| filter_relevantTo | Narrow to threats that have a specific relevance to my organization | Optional | 
| filter_tagOperator | Whether multiple tags should be logically applied as AND/OR with the resultset | Optional | 
| filter_tags | Limit to threats related to these tags only | Optional | 
| filter_threatLevels | Only include threats with one of these threat levels | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DigitalShadows.IntelligenceThreatsRegional.ActivityLevel | unknown | Level of activity, based on last active | 
| DigitalShadows.IntelligenceThreatsRegional.Id | unknown | Unique integer identifier \(among threats\) | 
| DigitalShadows.IntelligenceThreatsRegional.ImageId | unknown | The unique identifier for an image of the threat, if available. The actual image can be retrieved by requesting /api/resources/\{id\} \(replacing \{id\} with the value of this property\) | 
| DigitalShadows.IntelligenceThreatsRegional.LastActive | unknown | The date of last activity \(last incident\) | 
| DigitalShadows.IntelligenceThreatsRegional.Type | unknown | The type of profile being represented | 
| DigitalShadows.IntelligenceThreatsRegional.ThreatLevelType | unknown | Information about the level of threat, for example low or high | 
| DigitalShadows.IntelligenceThreatsRegional.Event | unknown | For an EVENT or CAMPAIGN threat this will contain a summary of when it occurred and possibly when it will re-occur | 


#### Command Example
```!ds-find-intelligence-threats filter_dateRange=2016-08-16T19:55:00.000Z/2016-08-16T19:55:00.000Z```

#### Context Example
```json
{
    "DigitalShadows": {
        "IntelligenceThreats": {
            "ActivityLevel": "INACTIVE",
            "Event": null,
            "Id": 5013,
            "ImageId": null,
            "LastActive": "2016-08-16T19:55:00.000Z",
            "ThreatLevelType": "LOW",
            "Type": "SPECIFIC_TTP"
        }
    }
}
```

#### Human Readable Output

>### Digital Shadows Intelligence Threats
> ActivityLevel| Event| Id| ImageId| LastActive| ThreatLevelType| Type
>---|---|---|---|---|---|---
>INACTIVE |   | 5013 |   | 2016-08-16T19:55:00.000Z | LOW | SPECIFIC_TTP


### ds-find-intelligence-threats-regional
***
Threat profiles associated with incidents over a given time range


#### Base Command

`ds-find-intelligence-threats-regional`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| countryTag_created | When was this tag created. | Optional | 
| countryTag_description | Description text for this tag. | Optional | 
| countryTag_id | Unique integer identifier for this tag | Optional | 
| countryTag_name | The name of this tag. Is unique in combination with the type | Optional | 
| countryTag_parent_id | Parent id of the tag | Optional | 
| countryTag_threat_id | Unique integer identifier (among threats). | Optional | 
| countryTag_threat_type | The type of profile being represented. | Optional | 
| countryTag_type | The type of this tag. The name of tags with the same type must be unique. | Optional | 
| filter_dateRange | Determines the interval the incidents must have occurred within to be included. Supports ISO Periods (eg P1D), intervals (eg 2015-01-01T00:00:00Z/2015-01-31T00:00:00Z) and any one of the constants {TODAY, YESTERDAY, WEEK, LAST_WEEK, MONTH, LAST_MONTH, YEAR, LAST_YEAR}. | Optional | 
| filter_periodRelativeTo | Optional timestamp that will be used as the end date for a period based dateRange. If not specified, then the end of the current day (based on the requesting user's timezone) will be used. | Optional | 
| filter_tagType | What types of tags should be considered. Should be one of SOURCE_GEOGRAPHY or TARGET_GEOGRAPHY (the default) | Optional | 
| regionTag_created | When was this tag created. | Optional | 
| regionTag_description | Description text for this tag. | Optional | 
| regionTag_id | Unique integer identifier for this tag | Optional | 
| regionTag_name | The name of this tag. Is unique in combination with the type | Optional | 
| regionTag_parent_id | Parent id of the tag | Optional | 
| regionTag_threat_id | Unique integer identifier (among threats). | Optional | 
| regionTag_threat_type | The type of profile being represented. | Optional | 
| regionTag_type | The type of this tag. The name of tags with the same type must be unique. | Optional | 
| threat_id | Id of the threat | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DigitalShadows.IntelligenceThreatsRegional.ActivityLevel | unknown | Level of activity, based on last active | 
| DigitalShadows.IntelligenceThreatsRegional.Id | unknown | Unique integer identifier \(among threats\) | 
| DigitalShadows.IntelligenceThreatsRegional.ImageId | unknown | The unique identifier for an image of the threat, if available. The actual image can be retrieved by requesting /api/resources/\{id\} \(replacing \{id\} with the value of this property\) | 
| DigitalShadows.IntelligenceThreatsRegional.LastActive | unknown | The date of last activity \(last incident\) | 
| DigitalShadows.IntelligenceThreatsRegional.Type | unknown | The type of profile being represented | 
| DigitalShadows.IntelligenceThreatsRegional.ThreatLevelType | unknown | Information about the level of threat, for example low or high | 
| DigitalShadows.IntelligenceThreatsRegional.Event | unknown | For an EVENT or CAMPAIGN threat this will contain a summary of when it occurred and possibly when it will re-occur | 
| DigitalShadows.IntelligenceThreatsRegional.OverviewTags | unknown | Tags that will appear in the overview. Only one per primary type. | 


#### Command Example
``` ```

#### Human Readable Output



### ds-get-port-reviews
***
Retrieve all review updates for a given port inspection


#### Base Command

`ds-get-port-reviews`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| port | Port inspection id | Required | 
| incidentId | ID of incident to query | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DigitalShadows.IpPortReviews.Created | unknown | The moment in time the review was created | 
| DigitalShadows.IpPortReviews.Status | unknown | Review status | 
| DigitalShadows.IpPortReviews.Version | unknown | Starts counting at 1 and increments for each review of a given port. Will initially be 0 until a review is performed \(when returned as part of a port\) | 
| DigitalShadows.IpPortReviews.Incident.Id | unknown | Id of the incident the port inspection is associated with | 
| DigitalShadows.IpPortReviews.Incident.Scope | unknown | Scope of the incident the port inspection is associated with | 
| DigitalShadows.IpPortReviews.User.Id | unknown | ID of the user that changed the status/set the note. | 
| DigitalShadows.IpPortReviews.User.FullName | unknown | Full name of the user that changed the status/set the note. | 


#### Command Example
``` ```

#### Human Readable Output



### ds-snapshot-port-review
***
Snapshot the review status of a port inspection


#### Base Command

`ds-snapshot-port-review`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| port | Port inspection id | Required | 
| version | When submitting, this value can be optionally set to the version of the most recently read review | Optional | 
| status | Review status | Optional | 
| incident_id | Identifier for this incident, unique in combination with the scope. | Optional | 
| incident_scope | Identifies whether this incident applies globally (intelligence) or just to your organization. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### ds-find-ports
***
Find ports


#### Base Command

`ds-find-ports`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter_alerted | Only include SSL/certificates with associated incidents that have been alerted | Optional | 
| filter_detectedClosed | Only return IP ports that were detected closed | Optional | 
| filter_detectedOpen | Only return IP ports that were detected open within this date range (inclusive). Supports ISO Periods (eg P1D), intervals (eg 2015-01-01T00:00:00Z/2015-01-31T00:00:00Z) and any one of the constants {TODAY, YESTERDAY, WEEK, LAST_WEEK, MONTH, LAST_MONTH, YEAR, LAST_YEAR}. | Optional | 
| filter_domainName | Name of domain to filter by | Optional | 
| filter_incidentTypes | The type to match to. Will match to any incident with this type unless subTypes is not empty, in which case only incident matches based on the sub-type will be considered. | Optional | 
| filter_incidentSubTypes | List of pecific sub type(s) to match to. String values from BRAND_MISUSE, COMPANY_THREAT, CORPORATE_INFORMATION, CREDENTIAL_COMPROMISE, CUSTOMER_DETAILS, CVE, DEFAMATION, DOMAIN_CERTIFICATE_ISSUE, EMPLOYEE_THREAT, EXPOSED_PORT, INTELLECTUAL_PROPERTY, INTERNALLY_MARKED_DOCUMENT, LEGACY_MARKED_DOCUMENT, MOBILE_APPLICATION, NEGATIVE_PUBLICITY, PERSONAL_INFORMATION, PHISHING_ATTEMPT, PROTECTIVELY_MARKED_DOCUMENT, SPOOF_PROFILE, TECHNICAL_INFORMATION,TECHNICAL_LEAKAGE, UNMARKED_DOCUMENT | Optional | 
| filter_ipAddress | IP address to filter by | Optional | 
| filter_ipRange_lowerAddress | Lower address for ip range | Optional | 
| filter_ipRange_maskBits | Int value for mask bits | Optional | 
| filter_ipRange_upperAddress | Upper address for ip range | Optional | 
| filter_markedClosed | Is incident closed | Optional | 
| filter_published | Only return IP ports that were published within this date range (inclusive). Supports ISO Periods (eg P1D), intervals (eg 2015-01-01T00:00:00Z/2015-01-31T00:00:00Z) and any one of the constants {TODAY, YESTERDAY, WEEK, LAST_WEEK, MONTH, LAST_MONTH, YEAR, LAST_YEAR}. | Optional | 
| filter_severities | Only include SSL/certificate infrastructure incidents with these severities. String values from VERY_HIGH, HIGH, MEDIUM, LOW, VERY_LOW, NONE | Optional | 
| sort_direction | The direction of sorting. If not specified, ASCENDING is assumed | Optional | 
| sort_property | The name of the property being sorted on. This normally corresponds to the property name of the result type, but could be a 'virtual property'. | Optional | 
| pagination_offset | Include results at this offset within the full resultset, where the first result is at position 0 | Optional | 
| pagination_size | Maximum number of results to return per page, can be initially null to be replaced by default later | Optional | 
| pagination_containingId | Select the page containing the record with this id, if supported. Mutually exclusive with offset. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DigitalShadows.IpPorts.DiscoveredOpen | unknown | When was the port found to be open | 
| DigitalShadows.IpPorts.Id | unknown | Identifier for the port inspection | 
| DigitalShadows.IpPorts.IpAddress | unknown | The IP address this port was found on | 
| DigitalShadows.IpPorts.PortNumber | unknown | The IP port number scanned \(1-65535\) | 
| DigitalShadows.IpPorts.Transport | unknown | IP transport protocol used | 
| DigitalShadows.IpPorts.Incident.Id | unknown | Id the most recent incident to include this port | 
| DigitalShadows.IpPorts.Incident.Scope | unknown | Scope of the most recent incident to include this port | 
| DigitalShadows.IpPorts.Incident.Severity | unknown | Severity of the most recent incident to include this port | 
| DigitalShadows.IpPorts.Incident.SubType | unknown | Subtype of the most recent incident to include this port | 
| DigitalShadows.IpPorts.Incident.Type | unknown | Type of the most recent incident to include this port | 
| DigitalShadows.IpPorts.Incident.Title | unknown | Title of the most recent incident to include this port | 
| DigitalShadows.IpPorts.Incident.Published | unknown | Published time the most recent incident to include this port | 
| DigitalShadows.IpPorts.Review.Status | unknown | Status of when the port was last reviewed | 
| DigitalShadows.IpPorts.Review.UserId | unknown | User Id of the port last review | 
| DigitalShadows.IpPorts.Review.UserName | unknown | Name of user who created last review | 
| DigitalShadows.IpPorts.Review.Version | unknown | Version of last port review | 


#### Command Example
```!ds-find-ports pagination_size=1```

#### Context Example
```json
{
    "DigitalShadows": {
        "IpPorts": [
            {
                "DiscoveredOpen": "2018-08-22T00:58:07.014Z",
                "Id": 8247047,
                "Incident": {
                    "Id": 99002722,
                    "Published": "2020-11-03T21:44:41.840Z",
                    "Scope": "ORGANIZATION",
                    "Severity": "MEDIUM",
                    "SubType": "EXPOSED_PORT",
                    "Title": "Blacklisted open ports found on IP",
                    "Type": "INFRASTRUCTURE"
                },
                "IpAddress": "1.2.3.4",
                "PortNumber": 179,
                "Review": {
                    "Status": "OPEN",
                    "UserId": null,
                    "UserName": null,
                    "Version": null
                },
                "Transport": "TCP"
            }
        ]
    }
}
```

#### Human Readable Output

>### Digital Shadows Ports
> DiscoveredOpen| Id| Incident Id| Incident Published| Incident Scope| Incident Severity| Incident SubType| Incident Title| Incident Type| IpAddress| PortNumber| Review Status| Review UserId| Review UserName| Review Version| Transport
>---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---
>2018-08-22T00:58:07.014Z | 8247047 | 99002722 | 2020-11-03T21:44:41.840Z | ORGANIZATION | MEDIUM | EXPOSED_PORT | Blacklisted open ports found on IP | INFRASTRUCTURE | 1.2.3.4 | 179 | OPEN |   |   |   | TCP


### ds-find-secure-sockets
***
Find secure sockets


#### Base Command

`ds-find-secure-sockets`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter_alerted | Only include SSL/certificates with associated incidents that have been alerted | Optional | 
| filter_detected | Only include detected sockets | Optional | 
| filter_determinedResolved | Only include determined resolved sockets | Optional | 
| filter_domain | Filter by domain | Optional | 
| filter_expiry | Filter by expiry date | Optional | 
| filter_grades | List of grades (A,B,C,D,E,F,T) | Optional | 
| filter_incidentTypes | The type to match to. Will match to any incident with this type unless subTypes is not empty, in which case only incident matches based on the sub-type will be considered. | Optional | 
| filter_incidentSubTypes | List of pecific sub type(s) to match to. String values from BRAND_MISUSE, COMPANY_THREAT, CORPORATE_INFORMATION, CREDENTIAL_COMPROMISE, CUSTOMER_DETAILS, CVE, DEFAMATION, DOMAIN_CERTIFICATE_ISSUE, EMPLOYEE_THREAT, EXPOSED_PORT, INTELLECTUAL_PROPERTY, INTERNALLY_MARKED_DOCUMENT, LEGACY_MARKED_DOCUMENT, MOBILE_APPLICATION, NEGATIVE_PUBLICITY, PERSONAL_INFORMATION, PHISHING_ATTEMPT, PROTECTIVELY_MARKED_DOCUMENT, SPOOF_PROFILE, TECHNICAL_INFORMATION,TECHNICAL_LEAKAGE, UNMARKED_DOCUMENT | Optional | 
| filter_ipAddress | IP address to filter by | Optional | 
| filter_issues | List of string values from POODLE, POODLE_TLS, FREAK, DROWN, LOGJAM, RC4_AVAILABLE, SELF_SIGNED, MD5_OR_SHA1_SIGNED, REVOKED, EXPIRING_LOW, EXPIRING_MEDIUM, EXPIRING_HIGH, EXPIRED, HOSTNAME_MISMATCH, TLS_1_2_NOT_FOUND | Optional | 
| filter_markedClosed | Is incident closed | Optional | 
| filter_published | Filter by publish time | Optional | 
| filter_revoked | Only include revoked sockets | Optional | 
| filter_severities | Only include SSL/certificate infrastructure incidents with these severities. String values from VERY_HIGH, HIGH, MEDIUM, LOW, VERY_LOW, NONE | Optional | 
| filter_statuses | Only include SSL/certificates with associated incidents having these statuses, (or with any status if none are supplied). UNREAD, READ, CLOSED | Optional | 
| sort_direction | The direction of sorting. If not specified, ASCENDING is assumed | Optional | 
| sort_property | The name of the property being sorted on. This normally corresponds to the property name of the result type, but could be a 'virtual property'. | Optional | 
| pagination_offset | Include results at this offset within the full resultset, where the first result is at position 0 | Optional | 
| pagination_size | Maximum number of results to return per page, can be initially null to be replaced by default later | Optional | 
| pagination_containingId | Select the page containing the record with this id, if supported. Mutually exclusive with offset. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DigitalShadows.SecureSockets.Id | unknown | Unique identifier for this inspection | 
| DigitalShadows.SecureSockets.ReverseDomainName | unknown | The reverse DNS name of the host | 
| DigitalShadows.SecureSockets.CertificateCommonName | unknown | The server certificate common name | 
| DigitalShadows.SecureSockets.Discovered | unknown | When were the certificate issue\(s\) found | 
| DigitalShadows.SecureSockets.DomainName | unknown | The domain name the secure socket was discovered on for the default port 443/TCP | 
| DigitalShadows.SecureSockets.Grade | unknown | The rating calculated for the secure socket at the time of the scan | 
| DigitalShadows.SecureSockets.IpAddress | unknown | The actual IP address the probe connected to | 
| DigitalShadows.SecureSockets.PortNumber | unknown | The port number the socket was found listening on | 
| DigitalShadows.SecureSockets.Transport | unknown | IP transport protocol used, most likely TCP | 
| DigitalShadows.SecureSockets.Issues | unknown | The set of issues detected for the secure socket | 
| DigitalShadows.SecureSockets.Review.Status | unknown | Status of most recent review of this inspection | 
| DigitalShadows.SecureSockets.Review.UserId | unknown | ID of user who created the most recent review of this inspection | 
| DigitalShadows.SecureSockets.Review.UserName | unknown | Name of user who created the most recent review of this inspection | 
| DigitalShadows.SecureSockets.Review.Version | unknown | Version of most recent review of this inspection | 
| DigitalShadows.SecureSockets.Incident.Id | unknown | Incident corresponding for this secure socket issues occurence | 
| DigitalShadows.SecureSockets.Incident.Scope | unknown | Scope of incident corresponding for this secure socket issues occurence | 
| DigitalShadows.SecureSockets.Incident.Severity | unknown | Severity of incident corresponding for this secure socket issues occurence | 
| DigitalShadows.SecureSockets.Incident.SubType | unknown | SubType of incident corresponding for this secure socket issues occurence | 
| DigitalShadows.SecureSockets.Incident.Type | unknown | Type of incident corresponding for this secure socket issues occurence | 
| DigitalShadows.SecureSockets.Incident.Title | unknown | Title of incident corresponding for this secure socket issues occurence | 
| DigitalShadows.SecureSockets.Incident.Published | unknown | Published time of incident corresponding for this secure socket issues occurence | 


### ds-find-vulnerabilities
***
Find vulnerabilities


#### Base Command

`ds-find-vulnerabilities`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter_alerted | Only include SSL/certificates with associated incidents that have been alerted | Optional | 
| filter_cveIdentifiers | Filter by CVE identifiers | Optional | 
| filter_detected | Only return vulnerabilities that were detected within this date range (inclusive). Supports ISO Periods (eg P1D), intervals (eg 2015-01-01T00:00:00Z/2015-01-31T00:00:00Z) and any one of the constants {TODAY, YESTERDAY, WEEK, LAST_WEEK, MONTH, LAST_MONTH, YEAR, LAST_YEAR}. | Optional | 
| filter_detectedClosed | True or false | Optional | 
| filter_domainName | Name of domain to filter by | Optional | 
| filter_incidentTypes | The type to match to. Will match to any incident with this type unless subTypes is not empty, in which case only incident matches based on the sub-type will be considered. | Optional | 
| filter_incidentSubTypes | List of pecific sub type(s) to match to. String values from BRAND_MISUSE, COMPANY_THREAT, CORPORATE_INFORMATION, CREDENTIAL_COMPROMISE, CUSTOMER_DETAILS, CVE, DEFAMATION, DOMAIN_CERTIFICATE_ISSUE, EMPLOYEE_THREAT, EXPOSED_PORT, INTELLECTUAL_PROPERTY, INTERNALLY_MARKED_DOCUMENT, LEGACY_MARKED_DOCUMENT, MOBILE_APPLICATION, NEGATIVE_PUBLICITY, PERSONAL_INFORMATION, PHISHING_ATTEMPT, PROTECTIVELY_MARKED_DOCUMENT, SPOOF_PROFILE, TECHNICAL_INFORMATION,TECHNICAL_LEAKAGE, UNMARKED_DOCUMENT | Optional | 
| filter_ipAddress | IP address to filter by | Optional | 
| filter_markedClosed | Filter by incidents that are marked as CLOSED | Optional | 
| filter_published | Only return vulnerabilities that were published within this date range (inclusive). Supports ISO Periods (eg P1D), intervals (eg 2015-01-01T00:00:00Z/2015-01-31T00:00:00Z) and any one of the constants {TODAY, YESTERDAY, WEEK, LAST_WEEK, MONTH, LAST_MONTH, YEAR, LAST_YEAR}. | Optional | 
| filter_severities | List of sevirity values to filter by. Can be VERY_HIGH, HIGH, MEDIUM, LOW, VERY_LOW, NONE | Optional | 
| sort_direction | The direction of sorting. If not specified, ASCENDING is assumed | Optional | 
| sort_property | The name of the property being sorted on. This normally corresponds to the property name of the result type, but could be a 'virtual property'. | Optional | 
| pagination_offset | Include results at this offset within the full resultset, where the first result is at position 0 | Optional | 
| pagination_size | Maximum number of results to return per page, can be initially null to be replaced by default later | Optional | 
| pagination_containingId | Select the page containing the record with this id, if supported. Mutually exclusive with offset. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DigitalShadows.Vulnerabilities.CveId | unknown | The CVE id | 
| DigitalShadows.Vulnerabilities.Id | unknown | Identifier for this detected vulnerability | 
| DigitalShadows.Vulnerabilities.Discovered | unknown | When was the vulnerability found | 
| DigitalShadows.Vulnerabilities.IpAddress | unknown | The IP address this port was found on | 
| DigitalShadows.Vulnerabilities.Review.Status | unknown | Status of most recent review of this vulnerability | 
| DigitalShadows.Vulnerabilities.Review.UserId | unknown | ID of user who created the most recent review of this vulnerability | 
| DigitalShadows.Vulnerabilities.Review.UserName | unknown | Name of user who created the most recent review of this vulnerability | 
| DigitalShadows.Vulnerabilities.Review.Version | unknown | Version of most recent review of this vulnerability | 
| DigitalShadows.Vulnerabilities.Incident.Id | unknown | ID of incident corresponding for this vulnerability occurence | 
| DigitalShadows.Vulnerabilities.Incident.Scope | unknown | Scope of incident corresponding for this vulnerability occurence | 
| DigitalShadows.Vulnerabilities.Incident.Severity | unknown | Severity of incident corresponding for this vulnerability occurence | 
| DigitalShadows.Vulnerabilities.Incident.SubType | unknown | SubType of incident corresponding for this vulnerability occurence | 
| DigitalShadows.Vulnerabilities.Incident.Type | unknown | Type of incident corresponding for this vulnerability occurence | 
| DigitalShadows.Vulnerabilities.Incident.Title | unknown | Title of incident corresponding for this vulnerability occurence | 
| DigitalShadows.Vulnerabilities.Incident.Published | unknown | Published of incident corresponding for this vulnerability occurence | 


#### Command Example
```!ds-find-vulnerabilities pagination_size=2```

#### Context Example
```json
{
    "DigitalShadows": {
        "Vulnerabilities": [
            {
                "CveId": "CVE-id",
                "Discovered": "2018-04-12T14:15:51.991Z",
                "Id": 529072,
                "Incident": {
                    "Id": 99002720,
                    "Published": "2020-11-04T17:32:57.855Z",
                    "Scope": "ORGANIZATION",
                    "Severity": "VERY_HIGH",
                    "SubType": "CVE",
                    "Title": "CVE with 4 exploits detected on 1.2.3.4.\r\n",
                    "Type": "INFRASTRUCTURE"
                },
                "IpAddress": "1.2.3.4",
                "Review": {
                    "Status": "UNREAD",
                    "UserId": null,
                    "UserName": null,
                    "Version": null
                }
            },
            {
                "CveId": "CVE-2018-6789",
                "Discovered": "2019-01-27T17:39:55.428Z",
                "Id": 879356,
                "Incident": {
                    "Id": 99002711,
                    "Published": "2020-11-04T23:54:22.672Z",
                    "Scope": "ORGANIZATION",
                    "Severity": "HIGH",
                    "SubType": "CVE",
                    "Title": "CVE with 2 exploits detected on 2.2.2.2",
                    "Type": "INFRASTRUCTURE"
                },
                "IpAddress": "2.2.2.2",
                "Review": {
                    "Status": "UNREAD",
                    "UserId": null,
                    "UserName": null,
                    "Version": null
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### Digital Shadows Vulnerabilities
> CveId| Discovered| Id| Incident Id| Incident Published| Incident Scope| Incident Severity| Incident SubType| Incident Title| Incident Type| IpAddress| Review Status| Review UserId| Review UserName| Review Version
>---|---|---|---|---|---|---|---|---|---|---|---|---|---|---
>CVE-id | 2018-04-12T14:15:51.991Z | 529072 | 99002720 | 2020-11-04T17:32:57.855Z | ORGANIZATION | VERY_HIGH | CVE | CVE with 4 exploits detected on 1.2.3.4.<br/> | INFRASTRUCTURE | 1.2.3.4 | UNREAD |   |   |  
>CVE-id | 2019-01-27T17:39:55.428Z | 879356 | 99002711 | 2020-11-04T23:54:22.672Z | ORGANIZATION | HIGH | CVE | CVE with 2 exploits detected on 2.2.2.2 | INFRASTRUCTURE | 2.2.2.2 | UNREAD |   |   |  


### ds-search
***
Perform a textual search against the available record types


#### Base Command

`ds-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter_datePeriod | Only return results that occurred during the given period prior to the current time. For absolute dates, use from and until | Optional | 
| filter_dateRange | Only return results that were verified/occurred/modified within this date range (inclusive). The field this applies to is controlled by dateRangeField. Supports ISO Periods (eg P1D), intervals (eg 2015-01-01T00:00:00Z/2015-01-31T00:00:00Z) and any one of the constants {TODAY, YESTERDAY, WEEK, LAST_WEEK, MONTH, LAST_MONTH, YEAR, LAST_YEAR}. | Optional | 
| filter_from | Only return results that were last active after this date/time (inclusive) | Optional | 
| filter_tags | Only return results that have the following tags associated with them. | Optional | 
| filter_types | Restrict the result types to only those listed here. At least one value is required. | Optional | 
| filter_until | Only return results that were last active before this date/time (inclusive) | Optional | 
| query | The query text to search for. | Optional | 
| sort_direction | The direction of sorting. If not specified, ASCENDING is assumed | Optional | 
| sort_property | The name of the property being sorted on. This normally corresponds to the property name of the result type, but could be a 'virtual property'. | Optional | 
| pagination_offset | Include results at this offset within the full resultset, where the first result is at position 0 | Optional | 
| pagination_size | Maximum number of results to return per page, can be initially null to be replaced by default later | Optional | 
| pagination_containingId | Select the page containing the record with this id, if supported. Mutually exclusive with offset. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!ds-search query=breach pagination_size=1```



#### Human Readable Output

>{"content":[{"entity":{"author":"name","id":"id","observableCounts":{"cve":{"count":1,"exceededMaximum":false},"email":{"count":0,"exceededMaximum":false},"host":{"count":0,"exceededMaximum":false},"ipV4":{"count":0,"exceededMaximum":false},"md5":{"count":0,"exceededMaximum":false},"sha1":{"count":0,"exceededMaximum":false},"sha256":{"count":0,"exceededMaximum":false}},"published":"2016-05-16T00:00:00.000Z","screenshot":{"id":"id,"link":"https://portal-digitalshadows.com/api/external/resources/id"},"screenshotThumbnail":{"id":"id","link":"https://portal-digitalshadows.com/api/thumbnails/id.jpg"},"siteCategories":["BLOG","SECURITY_COMMENTATOR"],"title":"The popular crime forum nnn...","sortDate":"2016-05-16T00:00:00.000Z","type":"BLOG_POST"}],"currentPage":{"offset":0,"size":1},"facets":{},"total":284483}

### ds-get-tags
***
Batch retrieve specic tags by their ids


#### Base Command

`ds-get-tags`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | One or more tag identifiers | Optional | 
| detailed | Determines whether the tag descriptions will be included. | Optional | 


#### Context Output

There is no context output for this command.
