Cloud-based SaaS to detect risks found on social media and digital channels.
This integration was integrated and tested with version xx of ZeroFoxKeyIncidents.

## Configure ZeroFox Key Incidents in Cortex


| **Parameter** | **Required** |
| --- | --- |
| URL (e.g., https://api.zerofox.com/) | True |
| Fetch incidents | False |
| Username | True |
| Password | True |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) | False |
| Incident type | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### zerofox-get-key-incident-attachment

***
Fetches a Key Incident Attachment by ID and uploads it to the current investigation War Room.

#### Base Command

`zerofox-get-key-incident-attachment`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| attachment_id | The ID of the Key Incident Attachment. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Size | Number | The size of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.SHA512 | String | The SHA512 hash of the file. | 
| File.Name | String | The name of the file. | 
| File.SSDeep | String | The SSDeep hash of the file. | 
| File.EntryID | String | The entry ID of the file. | 
| File.Info | String | File information. | 
| File.Type | String | The file type. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.Extension | String | The file extension. | 

## Incident Mirroring

You can enable incident mirroring between Cortex XSOAR incidents and ZeroFox Key Incidents corresponding events (available from Cortex XSOAR version 6.0.0).
To set up the mirroring:
1. Enable *Fetching incidents* in your instance configuration.

Newly fetched incidents will be mirrored in the chosen direction. However, this selection does not affect existing incidents.
**Important Note:** To ensure the mirroring works as expected, mappers are required, both for incoming and outgoing, to map the expected fields in Cortex XSOAR and ZeroFox Key Incidents.
