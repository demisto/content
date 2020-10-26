EmailRep.io Provides email address reputation and reports.
This integration was integrated and tested with version EmailRep Alpha API v0.1 of EmailRep.io
## Configure EmailRepIO on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for EmailRepIO.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server URL \(e.g. https://emailrep.io\) | True |
| apikey | API Key | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### emailrepio-email-reputation-get
***
Get EmailRepIO reputation for email address


#### Base Command

`emailrepio-email-reputation-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email_address | Email address to get reputation for | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EmailRepIO.Email.email | String | email address queried | 
| EmailRepIO.Email.reputation | String | high/medium/low/none | 
| EmailRepIO.Email.suspicious | Boolean | whether the email address should be treated as suspicious or risky | 
| EmailRepIO.Email.references | Number | total number of positive and negative sources of reputation. note that these may not all be direct references to the email address, but can include reputation sources for the domain or other related information | 
| EmailRepIO.Email.details.blacklisted | Boolean | the email is believed to be malicious or spammy | 
| EmailRepIO.Email.details.malicious_activity | Boolean | the email has exhibited malicious behavior \(e.g. phishing or fraud\) | 
| EmailRepIO.Email.details.malicious_activity_recent | Boolean | malicious behavior in the last 90 days \(e.g. in the case of temporal account takeovers\) | 
| EmailRepIO.Email.details.credentials_leaked | Boolean | credentials were leaked at some point in time \(e.g. a data breach, pastebin, dark web, etc.\) | 
| EmailRepIO.Email.details.credentials_leaked_recent | Boolean | credentials were leaked in the last 90 days | 
| EmailRepIO.Email.details.data_breach | Boolean | the email was in a data breach at some point in time | 
| EmailRepIO.Email.details.first_seen | Date | the first date the email was observed in a breach, credential leak, or exhibiting malicious or spammy behavior \(‘never’ if never seen\) | 
| EmailRepIO.Email.details.last_seen | Date | the last date the email was observed in a breach, credential leak, or exhibiting malicious or spammy behavior \(‘never’ if never seen\) | 
| EmailRepIO.Email.details.domain_exists | Boolean | valid domain | 
| EmailRepIO.Email.details.domain_reputation | String | high/medium/low/n/a \(n/a if the domain is a free_provider, disposable, or doesn’t exist\) | 
| EmailRepIO.Email.details.new_domain | Boolean | the domain was created within the last year | 
| EmailRepIO.Email.details.days_since_domain_creation | Number | days since the domain was created | 
| EmailRepIO.Email.details.suspicious_tld | Boolean | suspicious tld | 
| EmailRepIO.Email.details.spam | Boolean | the email has exhibited spammy behavior \(e.g. spam traps, login form abuse\) | 
| EmailRepIO.Email.details.free_provider | Boolean | the email uses a free email provider | 
| EmailRepIO.Email.details.disposable | Boolean | the email uses a temporary/disposable service | 
| EmailRepIO.Email.details.deliverable | Boolean | deliverable | 
| EmailRepIO.Email.details.accept_all | Boolean | whether the mail server has a default accept all policy. some mail servers return inconsistent responses, so we may default to an accept_all for those to be safe | 
| EmailRepIO.Email.details.valid_mx | Boolean | has an MX record | 
| EmailRepIO.Email.details.spoofable | Boolean | email address can be spoofed \(e.g. not a strict SPF policy or DMARC is not enforced\) | 
| EmailRepIO.Email.details.spf_strict | Boolean | sufficiently strict SPF record to prevent spoofing | 
| EmailRepIO.Email.details.dmarc_enforced | Boolean | DMARC is configured correctly and enforced | 
| EmailRepIO.Email.details.profiles | String | online profiles used by the email | 


#### Command Example
```!emailrepio-email-reputation-get email_address="test@example.com" ```



### email
***
Get DBot score for email address using EmailRepIO reputation


#### Base Command

`email`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | Email address to get reputation for | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| EmailRepIO.Email.email | String | email address queried | 
| EmailRepIO.Email.reputation | String | high/medium/low/none | 
| EmailRepIO.Email.suspicious | Boolean | whether the email address should be treated as suspicious or risky | 
| EmailRepIO.Email.references | Number | total number of positive and negative sources of reputation. note that these may not all be direct references to the email address, but can include reputation sources for the domain or other related information | 
| EmailRepIO.Email.details.blacklisted | Boolean | the email is believed to be malicious or spammy | 
| EmailRepIO.Email.details.malicious_activity | Boolean | the email has exhibited malicious behavior \(e.g. phishing or fraud\) | 
| EmailRepIO.Email.details.malicious_activity_recent | Boolean | malicious behavior in the last 90 days \(e.g. in the case of temporal account takeovers\) | 
| EmailRepIO.Email.details.credentials_leaked | Boolean | credentials were leaked at some point in time \(e.g. a data breach, pastebin, dark web, etc.\) | 
| EmailRepIO.Email.details.credentials_leaked_recent | Boolean | credentials were leaked in the last 90 days | 
| EmailRepIO.Email.details.data_breach | Boolean | the email was in a data breach at some point in time | 
| EmailRepIO.Email.details.first_seen | Date | the first date the email was observed in a breach, credential leak, or exhibiting malicious or spammy behavior \(‘never’ if never seen\) | 
| EmailRepIO.Email.details.last_seen | Date | the last date the email was observed in a breach, credential leak, or exhibiting malicious or spammy behavior \(‘never’ if never seen\) | 
| EmailRepIO.Email.details.domain_exists | Boolean | valid domain | 
| EmailRepIO.Email.details.domain_reputation | String | high/medium/low/n/a \(n/a if the domain is a free_provider, disposable, or doesn’t exist\) | 
| EmailRepIO.Email.details.new_domain | Boolean | the domain was created within the last year | 
| EmailRepIO.Email.details.days_since_domain_creation | Number | days since the domain was created | 
| EmailRepIO.Email.details.suspicious_tld | Boolean | suspicious tld | 
| EmailRepIO.Email.details.spam | Boolean | the email has exhibited spammy behavior \(e.g. spam traps, login form abuse\) | 
| EmailRepIO.Email.details.free_provider | Boolean | the email uses a free email provider | 
| EmailRepIO.Email.details.disposable | Boolean | the email uses a temporary/disposable service | 
| EmailRepIO.Email.details.deliverable | Boolean | deliverable | 
| EmailRepIO.Email.details.accept_all | Boolean | whether the mail server has a default accept all policy. some mail servers return inconsistent responses, so we may default to an accept_all for those to be safe | 
| EmailRepIO.Email.details.valid_mx | Boolean | has an MX record | 
| EmailRepIO.Email.details.spoofable | Boolean | email address can be spoofed \(e.g. not a strict SPF policy or DMARC is not enforced\) | 
| EmailRepIO.Email.details.spf_strict | Boolean | sufficiently strict SPF record to prevent spoofing | 
| EmailRepIO.Email.details.dmarc_enforced | Boolean | DMARC is configured correctly and enforced | 
| EmailRepIO.Email.details.profiles | String | online profiles used by the email | 


#### Command Example
```!email email="test@example.com" ```


### emailrepio-email-address-report
***
Report email address to EmailRepIO


#### Base Command

`emailrepio-email-address-report`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email_address | Email address being reported. | Required | 
| tags | Tags that should be applied. See detailed descriptions in EmailRepIO documentation for more information. | Required | 
| description | Additional information and context. | Optional | 
| timestamp | When this activity occurred in UTC. Defaults to now(). | Optional | 
| expires | Number of hours the email should be considered risky (suspicious=true and blacklisted=true in the QueryResponse). Defaults to no expiration unless account_takeover tag is specified, in which case the default is 14 days. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!emailrepio-email-address-report email_address="test@example.com" tags="spam"```


