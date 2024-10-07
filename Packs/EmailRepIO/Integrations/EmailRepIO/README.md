EmailRep.io provides the reputation and reports for email addresses.
This integration was integrated and tested with version EmailRep Alpha API v0.1 of EmailRep.io
## Configure EmailRepIO in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server URL \(e.g., https://emailrep.io\) | True |
| apikey | API Key | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| Source Reliability | Reliability of the source providing the intelligence data. | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### emailrepio-email-reputation-get
***
Gets the EmailRepIO reputation for the given email address.


#### Base Command

`emailrepio-email-reputation-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email_address | The email address to get the reputation for. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EmailRepIO.Email.email | String | The email address that was queried. | 
| EmailRepIO.Email.reputation | String | The reputation of the email. Possible values are: "high", "medium", "low", and "none". | 
| EmailRepIO.Email.suspicious | Boolean | Whether the email address should be treated as suspicious or risky. | 
| EmailRepIO.Email.references | Number | The total number of positive and negative sources of the reputation. Note that these may not all be direct references to the email address, but can include reputation sources for the domain or other related information. | 
| EmailRepIO.Email.details.blacklisted | Boolean | Whether the email is believed to be malicious or spam. | 
| EmailRepIO.Email.details.malicious_activity | Boolean | Whether the email exhibited malicious behavior \(e.g., phishing or fraud\). | 
| EmailRepIO.Email.details.malicious_activity_recent | Boolean | Whether the email exhibited malicious behavior in the last 90 days \(e.g., in the case of temporal account takeovers\). | 
| EmailRepIO.Email.details.credentials_leaked | Boolean | Whether the email credentials were ever leaked \(e.g., a data breach, pastebin, dark web, etc.\). | 
| EmailRepIO.Email.details.credentials_leaked_recent | Boolean | Whether the email credentials were leaked in the last 90 days. | 
| EmailRepIO.Email.details.data_breach | Boolean | Whether the email was ever in a data breach. | 
| EmailRepIO.Email.details.first_seen | Date | The first date the email was observed in a breach, credential leak, or exhibiting malicious or spammy behavior. Displays "never" if the email was never observed in a breach, credential leak, or exhibiting malicious or spammy behavior. | 
| EmailRepIO.Email.details.last_seen | Date | The last date the email was observed in a breach, credential leak, or exhibiting malicious or spammy behavior. Displays "never" if the email was never observed in a breach, credential leak, or exhibiting malicious or spammy behavior. | 
| EmailRepIO.Email.details.domain_exists | Boolean | Whether the domain is a valid domain. | 
| EmailRepIO.Email.details.domain_reputation | String | The reputation of the domain. Possible values are: "high", "medium", "low", and "n/a". Displays "n/a" if the domain is a free_provider, disposable, or doesn’t exist. | 
| EmailRepIO.Email.details.new_domain | Boolean | Whether the domain was created within the last year. | 
| EmailRepIO.Email.details.days_since_domain_creation | Number | The number of days since the domain was created. | 
| EmailRepIO.Email.details.suspicious_tld | Boolean | Whether the email has a suspicious top level domain (tld). | 
| EmailRepIO.Email.details.spam | Boolean | Whether the email has exhibited spammy behavior  \(e.g., spam traps, login form abuse\). | 
| EmailRepIO.Email.details.free_provider | Boolean | Whether the email uses a free email provider. | 
| EmailRepIO.Email.details.disposable | Boolean | Whether the email uses a temporary or disposable service. | 
| EmailRepIO.Email.details.deliverable | Boolean | Whether the email is deliverable. | 
| EmailRepIO.Email.details.accept_all | Boolean | Whether the mail server has a default accept all policy. Some mail servers return inconsistent responses, so the default may be an accept all policy. | 
| EmailRepIO.Email.details.valid_mx | Boolean | Whether the email has a mail exchanger (MX) record. | 
| EmailRepIO.Email.details.spoofable | Boolean | Whether the email address can be spoofed \(e.g., not a strict SPF policy or DMARC is not enforced\). | 
| EmailRepIO.Email.details.spf_strict | Boolean |  Whether there is a sufficiently strict SPF record to prevent spoofing. | 
| EmailRepIO.Email.details.dmarc_enforced | Boolean | Whether DMARC is configured correctly and enforced. | 
| EmailRepIO.Email.details.profiles | String | The online profiles used by the email. | 


#### Command Example
```!emailrepio-email-reputation-get email_address="test@example.com" ```



### email
***
Gets the DBot score for the given email address using the EmailRepIO reputation.


#### Base Command

`email`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | The email address to get the reputation for. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual DBot score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| EmailRepIO.Email.email | String | email address that was queried | 
| EmailRepIO.Email.reputation | String | The reputation of the email. Possible values are: "high", "medium", "low", and "none". | 
| EmailRepIO.Email.suspicious | Boolean | Whether the email address should be treated as suspicious or risky. | 
| EmailRepIO.Email.references | Number | The total number of positive and negative sources of the reputation. Note that these may not all be direct references to the email address, but can include reputation sources for the domain or other related information. | 
| EmailRepIO.Email.details.blacklisted | Boolean | Whether the email is believed to be malicious or spam. | 
| EmailRepIO.Email.details.malicious_activity | Boolean | Whether the email exhibited malicious behavior \(e.g., phishing or fraud\). | 
| EmailRepIO.Email.details.malicious_activity_recent | Boolean | Whether the email exhibited malicious behavior in the last 90 days \(e.g., in the case of temporal account takeovers\). | 
| EmailRepIO.Email.details.credentials_leaked | Boolean | Whether the email credentials were ever leaked \(e.g., a data breach, pastebin, dark web, etc.\). | 
| EmailRepIO.Email.details.credentials_leaked_recent | Boolean | Whether the email credentials were leaked in the last 90 days. | 
| EmailRepIO.Email.details.data_breach | Boolean | Whether the email was ever in a data breach. | 
| EmailRepIO.Email.details.first_seen | Date | The first date the email was observed in a breach, credential leak, or exhibiting malicious or spammy behavior. Displays "never" if the email was never observed in a breach, credential leak, or exhibiting malicious or spammy behavior. | 
| EmailRepIO.Email.details.last_seen | Date | The last date the email was observed in a breach, credential leak, or exhibiting malicious or spammy behavior. Displays "never" if the email was never observed in a breach, credential leak,  or exhibiting malicious or spammy behavior. | 
| EmailRepIO.Email.details.domain_exists | Boolean | Whether the domain is a valid domain. | 
| EmailRepIO.Email.details.domain_reputation | String | The reputation of the domain. Possible values are: "high", "medium", "low", and "n/a". Displays "n/a" if the domain is a free_provider, disposable, or doesn’t exist. | 
| EmailRepIO.Email.details.new_domain | Boolean | Whether the domain was created within the last year. | 
| EmailRepIO.Email.details.days_since_domain_creation | Number | The number of days since the domain was created. | 
| EmailRepIO.Email.details.suspicious_tld | Boolean | Whether the email has a suspicious top level domain (tld). | 
| EmailRepIO.Email.details.spam | Boolean | Whether the email exhibited spammy behavior \(e.g., spam traps, login form abuse\). | 
| EmailRepIO.Email.details.free_provider | Boolean | Whether the email uses a free email provider. | 
| EmailRepIO.Email.details.disposable | Boolean | Whether the email uses a temporary or disposable service. | 
| EmailRepIO.Email.details.deliverable | Boolean | Whether the email is deliverable. | 
| EmailRepIO.Email.details.accept_all | Boolean | Whether the mail server has a default accept all policy. Some mail servers return inconsistent responses, so the default may be an accept all policy. | 
| EmailRepIO.Email.details.valid_mx | Boolean | Whether the email has a mail exchanger (MX) record. | 
| EmailRepIO.Email.details.spoofable | Boolean | Whether the email has a mail exchanger (MX) record. \(e.g., not a strict SPF policy or DMARC is not enforced\). | 
| EmailRepIO.Email.details.spf_strict | Boolean | Whether there is a sufficiently strict SPF record to prevent spoofing. | 
| EmailRepIO.Email.details.dmarc_enforced | Boolean | Whether DMARC is configured correctly and enforced. | 
| EmailRepIO.Email.details.profiles | String | The online profiles used by the email. | 


#### Command Example
```!email email="test@example.com" ```


### emailrepio-email-address-report
***
Reports a malicious email address to EmailRepIO.  You tag the type of malicious activity associated with the email address. The date of the malicious activity defaults to the current time unless otherwise specified.


#### Base Command

`emailrepio-email-address-report`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email_address | The email address to report. | Required | 
| tags | The tags that should be applied. See detailed descriptions in the EmailRepIO documentation for more information. | Required | 
| description | Additional information and context. | Optional | 
| timestamp |The time the activity occurred in UTC time format. Defaults to now(). | Optional | 
| expires | The number of hours the email should be considered risky (suspicious=true and blacklisted=true in the QueryResponse). Defaults to no expiration unless the "account_takeover" tag is specified, in which case the default is 14 days. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!emailrepio-email-address-report email_address="test@example.com" tags="spam"```

