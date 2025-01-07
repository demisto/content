An integration for Netcraft, allowing you to open and handle takedown requests.

## Configure Netcraft in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Credentials | True |
| Password | True |
| The maximum number of entries (takedowns/notes) to return. Default is 100. | False |
| Use system proxy settings | False |
| Trust any certificate (not secure) | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
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
| Netcraft.Takedown.IP | Unknown | The IPv4 address of the attack. | 
| Netcraft.Takedown.Domain | Unknown | 	The domain of the URL or email address being taken down. This will be blank for attacks without a domain name. | 
| Netcraft.Takedown.Hostname | Unknown | The full hostname of the URL or email address being taken down. This will be blank for attacks without a hostname. | 
| Netcraft.Takedown.CountryCode | Unknown | ISO country code of the hosting country. | 
| Netcraft.Takedown.DomainAttack | Unknown | Whether the domain is thought to be fraudulent. | 
| Netcraft.Takedown.TargetedURL | Unknown | The URL which this attack is masquerading as. For example, the URL of the legitimate login form that the attack targets. | 
| Netcraft.Takedown.Certificate | Unknown | TTPS certificate details for the hostname, or null if no certificate was found. The value returned is the output of PHP's openssl_x509_parse function. | 

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
| notify | Whether to notify Netcraft. Default is "true". Possible values are: True, False. | Optional | 


#### Context Output

There is no context output for this command.
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