This pack includes configurations to combine the world-class threat detection of Darktrace with the synchrony and automation abilities of XSOAR, allowing security teams to investigate critical incidents along with accompanying summaries and timelines.
This integration was integrated and tested with version xx of DarktraceEmail.

## Configure DarktraceEmail in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL (e.g. https://example.net) |  | True |
| Fetch incidents |  | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Incident type |  | False |
| Public API Token | Public token obtained by creating an API token pair on the /config configuration page. | True |
| Private API Token | Private token obtained by creating an API token pair on the /config configuration page. | True |
| Minimum Score | Minimum Darktrace score for fetched incidents \(0-100\). | True |
| Maximum Emails per Fetch | Maximum number of Darktrace Emails to fetch at a time. | False |
| First fetch time | Time to start fetching the first incidents. Default is to begin fetching 1 day ago. Max number of model breaches that will be populated upon first fetch is 20. | False |
| Incidents Fetch Interval |  | False |
| Darktrace Tag Severity | Fetches Emails with any tags of the desired severity level, filtering is inclusive.  By default fetches all severity levels. | False |
| Only Actioned Emails | Only fetch Emails that have been actioned. Disabled by default. | False |
| Direction | Fetch emails based on direction; either inbound, outbound or internal.  By default fetches all directions. | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### darktrace-email-get-email

***
Fetch details about a specific Email.

#### Base Command

`darktrace-email-get-email`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | Darktrace UUID of the Email. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Darktrace.Email.uuid | string | UUID of email. | 
| Darktrace.Email.direction | string | Direction of email. | 
| Darktrace.Email.dtime | string | Timestamp of email. | 
| Darktrace.Email.header_from_email | string | Email address of sender. | 
| Darktrace.Email.header_subject | string | Subject of email. | 
| Darktrace.Email.model_score | number | Anomaly score of email. | 
| Darktrace.Email.receipt_status | string | Receipt status of email. | 

### darktrace-email-hold-email

***
Apply "hold" action to a specified Email.

#### Base Command

`darktrace-email-hold-email`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | Unique ID of Email. | Required | 

#### Context Output

There is no context output for this command.
### darktrace-email-release-email

***
Apply "release" action to a specified Email. 

#### Base Command

`darktrace-email-release-email`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | Unique ID of Email. | Required | 
| recipient | Recipient of Email. Not required but speeds up the command. | Optional | 

#### Context Output

There is no context output for this command.
