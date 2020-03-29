Uses the Have I Been Pwned? service to check whether email addresses or domains were compromised in previous breaches.
This integration was integrated and tested with version xx of Have I Been Pwned? V2
## Configure Have I Been Pwned? V2 on Demisto

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Have I Been Pwned? V2.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| api_key | API Key | True |
| max_retry_time | Maximum time per request (in seconds) | False |
| default_dbot_score_email | Email Severity: The DBot reputation for compromised emails (SUSPICIOUS or MALICIOUS) | False |
| default_dbot_score_domain | Domain Severity: The DBot reputation for compromised domains (SUSPICIOUS or MALICIOUS) | False |
| insecure | Trust any certificate (not secure) | False |
| proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### pwned-email
***
Checks if an email address was compromised.


##### Base Command

`pwned-email`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | The email address to check (CSV supported). | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Account.Email.Pwned-V2.Compromised.Vendor | String | For compromised email addresses, the vendor that made the decision. | 
| Account.Email.Pwned-V2.Compromised.Reporters | String | For compromised email addresses, the reporters for the vendor to make the compromised decision. | 
| Account.Email.Address | String | The email address. | 
| Email.Malicious.Vendor | String | For malicious email addresses, the vendor that made the decision. | 
| Email.Malicious.Description | String | For malicious email addresses, the reason that the vendor made the decision. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | Vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 


##### Command Example
``` ```

##### Human Readable Output


### pwned-domain
***
Checks if a domain was compromised.


##### Base Command

`pwned-domain`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The domain to check (CSV supported). | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Pwned-V2.Compromised.Vendor | String | For compromised domains, the vendor that made the decision. | 
| Domain.Pwned-V2.Compromised.Reporters | String | For compromised domains, the reporters for the vendor to make the compromised decision. | 
| Domain.Name | String | Domain name. | 
| Domain.Malicious.Vendor | String | For malicious domains, the vendor that made the decision. | 
| Domain.Malicious.Description | String | For malicious domains, the reason that the vendor made the decision. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | Vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 


##### Command Example
``` ```

##### Human Readable Output


### email
***
Checks if an email address was compromised.


##### Base Command

`email`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | The email address to check (CSV supported). | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Account.Email.Pwned-V2.Compromised.Vendor | String | For compromised email addresses, the vendor that made the decision. | 
| Account.Email.Pwned-V2.Compromised.Reporters | String | For compromised email addresses, the reporters for the vendor to make the compromised decision. | 
| Account.Email.Address | String | The email address. | 
| Email.Malicious.Vendor | String | For malicious email addresses, the vendor that made the decision. | 
| Email.Malicious.Description | String | For malicious email addresses, the reason that the vendor made the decision. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 


##### Command Example
``` ```

##### Human Readable Output


### domain
***
Checks if a domain was compromised.


##### Base Command

`domain`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The domain to check (CSV supported). | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Pwned-V2.Compromised.Vendor | String | For compromised domains, the vendor that made the decision. | 
| Domain.Pwned-V2.Compromised.Reporters | String | For compromised domains, the reporters for the vendor to make the compromised decision. | 
| Domain.Name | String | The domain name. | 
| Domain.Malicious.Vendor | String | For malicious domains, the vendor that made the decision. | 
| Domain.Malicious.Description | String | For malicious domains, the reason that the vendor made the decision. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 


##### Command Example
``` ```

##### Human Readable Output


### username
***
Checks if a username was compromised.


##### Base Command

`username`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The username to check (CSV supported). | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Username.Pwned-V2.Compromised.Vendor | String | For compromised usernames, the vendor that made the decision. | 
| Username.Pwned-V2.Compromised.Reporters | String | For compromised usernames, the reporters for the vendor to make the compromised decision. | 
| Username.Name | String | The username name. | 
| Username.Malicious.Vendor | String | For malicious usernames, the vendor that made the decision. | 
| Username.Malicious.Description | String | For malicious username, the reason that the vendor made the decision. | 


##### Command Example
``` ```

##### Human Readable Output


### pwned-username
***
Checks if a username was compromised.


##### Base Command

`pwned-username`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The username to check (CSV supported). | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Username.Pwned-V2.Compromised.Vendor | String | For compromised usernames, the vendor that made the decision. | 
| Username.Pwned-V2.Compromised.Reporters | String | For compromised usernames, the reporters for the vendor to make the compromised decision. | 
| Username.Name | String | The username name. | 
| Username.Malicious.Vendor | String | For malicious usernames, the vendor that made the decision. | 
| Username.Malicious.Description | String | For malicious username, the reason that the vendor made the decision. | 


##### Command Example
``` ```

##### Human Readable Output

