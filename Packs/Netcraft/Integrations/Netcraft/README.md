An integration for Netcraft, allowing you to open and handle takedown requests.

## Configure Netcraft on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Netcraft.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| credentials | Credentials | True |
| limit | The maximum number of entries \(takedowns/notes\) to return. Default is 100. | False |
| proxy | Use system proxy settings | False |
| unsecure | Trust any certificate \(not secure\) | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### netcraft-report-attack
***
Reports an attack to Netcraft.


#### Base Command

`netcraft-report-attack`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| attack | The attack location you want taken down. For example, a phishing URL or fraudulent email address. | Required | 
| comment | The reason for submitting the attack, such as a description of the attack. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netcraft.Takedown.DateSubmitted | String | The date and time of reporting. | 
| Netcraft.Takedown.LastUpdated | String | The date and time of the last action taken on the takedown. | 
| Netcraft.Takedown.EvidenceURL | String | The URL of the evidence page on incident.netcraft.com. | 
| Netcraft.Takedown.Reporter | String | The person/account that submitted the takedown. | 
| Netcraft.Takedown.Domain | String | The domain of the URL or email address being taken down. This will be blank for attacks without a domain name. | 
| Netcraft.Takedown.Hostname | String | The full hostname of the URL or email address being taken down. This will be blank for attacks without a hostname. | 
| Netcraft.Takedown.CountryCode | String | ISO country code of the hosting country. | 
| Netcraft.Takedown.DomainAttack | String | Whether the domain is thought to be fraudulent. | 
| Netcraft.Takedown.TargetedURL | String | The URL that this attack is masquarading as. For example, the URL of the legitimate login form that the attack targets. | 
| Netcraft.Takedown.Certificate | Unknown | HTTPS certificate details for the hostname, or null if no certificate was found. The value returned is the output of PHP's openssl_x509_parse function. | 
| Netcraft.Takedown.ID | Number | The ID of the takedown. | 
| Netcraft.Takedown.GroupID | Number | The group ID of the takedown, can potentially be the same as ID, or empty if there is no group. | 
| Netcraft.Takedown.Status | String | The status of the takedown. | 
| Netcraft.Takedown.AttackType | String | The type of takedown. | 
| Netcraft.Takedown.AttackURL | String | The location of the attack being taken down. | 
| Netcraft.Takedown.Region | String | The customer area in which the attack resides. | 
| Netcraft.Takedown.IP | String | The IPv4 address of the attack. | 


#### Command Example
```!netcraft-report-attack attack=http://examp1eb4nk.com comment=Phishing```

#### Human Readable Output

>### New takedown successfully created


### netcraft-get-takedown-info
***
Returns information on existing takedowns. You can retrieve the takedown ID when you report the malicious URL and open the takedown, using the netcraft-report-attack command.


#### Base Command

`netcraft-get-takedown-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the takedowns for which to get information. | Optional | 
| date_from | Retrieve information for takedowns submitted after this date. Format: YYYY-MM-DD HH:MM:SS. | Optional | 
| updated_since | Retrieve information for takedowns updated after this date. Format: YYYY-MM-DD HH:MM:SS. | Optional | 
| url | The URL by which to filter. | Optional | 
| ip | The IP by which to filter. | Optional | 
| region | The region by which to filter. If the region is invalid or not specified, all regions are returned. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netcraft.Takedown.ID | number | The ID of the takedown. | 
| Netcraft.Takedown.GroupID | number | The group ID of the takedown, can potentially be the same as ID or empty if there is no group. | 
| Netcraft.Takedown.Status | string | The status of the takedown. | 
| Netcraft.Takedown.AttackType | string | The type of takedown. | 
| Netcraft.Takedown.AttackURL | string | The location of the attack being taken down. | 
| Netcraft.Takedown.Region | string | The customer area in which the attack resides. | 
| Netcraft.Takedown.DateSubmitted | string | The date and time of reporting. | 
| Netcraft.Takedown.LastUpdated | string | The date and time of the last action taken on the takedown. | 
| Netcraft.Takedown.EvidenceURL | string | The URL of the evidence page on incident.netcraft.com. | 
| Netcraft.Takedown.Reporter | string | The person/account that submitted the takedown. | 
| Netcraft.Takedown.IP | string | The IPv4 address of the attack. | 
| Netcraft.Takedown.Domain | string | 	The domain of the URL or email address being taken down. This will be blank for attacks without a domain name. | 
| Netcraft.Takedown.Hostname | string | The full hostname of the URL or email address being taken down. This will be blank for attacks without a hostname. | 
| Netcraft.Takedown.CountryCode | string | ISO country code of the hosting country. | 
| Netcraft.Takedown.DomainAttack | string | Whether the domain is thought to be fraudulent. | 
| Netcraft.Takedown.TargetedURL | string | The URL which this attack is masquerading as. For example, the URL of the legitimate login form that the attack targets. | 
| Netcraft.Takedown.Certificate | string | TTPS certificate details for the hostname, or null if no certificate was found. The value returned is the output of PHP's openssl_x509_parse function. | 


#### Command Example
```!netcraft-get-takedown-info id=2071408```

#### Context Example
```json
{
    "Netcraft": {
        "Takedown": {
            "AttackType": "phishing_url",
            "AttackURL": "http://examp1eb4nk.com",
            "Certificate": false,
            "CountryCode": "ca",
            "DateSubmitted": "2017-09-20 19:21:42 EEST",
            "Domain": "thdcr.com",
            "DomainAttack": "yes",
            "EvidenceURL": "https://incident.netcraft.com/5b3fcd01eb3a/",
            "GroupID": "2071408",
            "Hostname": "thdcr.com",
            "ID": "2071408",
            "IP": "199.188.70.150",
            "LastUpdated": "2020-10-12 06:27:50 EEST",
            "Region": "region",
            "Reporter": "netcraft",
            "Status": "Stale"
        }
    }
}
```

#### Human Readable Output

>### Takedowns information found:
>|ID|Status|Attack Type|Date Submitted|Last Updated|Reporter|Group ID|Region|Evidence URL|Attack URL|IP|Domain|Hostname|Country Code|Domain Attack|Certificate|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2071408 | Stale | phishing_url | 2017-09-20 19:21:42 EEST | 2020-10-12 06:27:50 EEST | netcraft | 2071408 | region | https://incident.netcraft.com/5b3fcd01eb3a/ | http://examp1eb4nk.com | 199.188.70.150 | thdcr.com | thdcr.com | ca | yes | false |


### netcraft-get-takedown-notes
***
Returns notes for takedowns.


#### Base Command

`netcraft-get-takedown-notes`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| takedown_id | The takedown to get notes for. | Optional | 
| group_id | A takedown group to get notes for. | Optional | 
| date_from | Retrieve notes created after this date. | Optional | 
| date_to | Retrieve notes created before this date. | Optional | 
| author | A specific user to get notes for. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netcraft.Takedown.Note.TakedownID | number | The ID of the takedown to which the note belongs. | 
| Netcraft.Takedown.Note.NoteID | number | The ID of the note. | 
| Netcraft.Takedown.Note.GroupID | number | If this note is attached to all takedowns in a group, group_id is the ID of that group. Otherwise, the value 0 means the note is sent to a single takedown. | 
| Netcraft.Takedown.Note.Author | string | The author of the note. "Netcraft" denotes a Netcraft authored note. | 
| Netcraft.Takedown.Note.Note | string | The content \(text\) of the note. | 
| Netcraft.Takedown.Note.Time | string | The date/time the note was created. Format \(UTC\): YYYY-MM-DD HH:MM:SS. | 


#### Command Example
```!netcraft-get-takedown-notes takedown_id=493542```

#### Context Example
```json
{
    "Netcraft": {
        "Takedown": {
            "ID": 493542,
            "Note": [
                {
                    "Author": "user@org.com",
                    "GroupID": 493542,
                    "Note": "Phishing",
                    "NoteID": 318587592,
                    "TakedownID": 493542,
                    "Time": "2020-11-23 13:44:46"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Takedowns information found:
>|Takedown ID|Note ID|Note|Author|Time|Group ID|
>|---|---|---|---|---|---|
>| 493542 | 318587592 | Phishing | user@org.com | 2020-11-23 13:44:46 | 493542 |


### netcraft-add-notes-to-takedown
***
Adds notes to an existing takedown.


#### Base Command

`netcraft-add-notes-to-takedown`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| takedown_id | A valid takedown ID to add the note to. | Required | 
| note | The text to add to the takedown. | Required | 
| notify | Whether to notify Netcraft. Default is "true". | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!netcraft-add-notes-to-takedown note=Phishing takedown_id=493542```

#### Context Example
```json
{
    "note_id": 318588887
}
```

#### Human Readable Output

>### Note added succesfully
>ID of the note created: 318588887

### netcraft-escalate-takedown
***
Escalates a takedown.


#### Base Command

`netcraft-escalate-takedown`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| takedown_id | The ID of the takedown to escalate. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!netcraft-escalate-takedown takedown_id=493542```


#### Human Readable Output

>### Takedown escalated successfully

## Troubleshooting
- If error message `TD_ERROR APPLICATION ERROR` returned, it could be because of no takedown credits remaining.