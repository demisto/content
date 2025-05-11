Creates mock email incidents using one of two randomly selected HTML templates. Textual content is randomly generated and defined to include some text (100 random words) and the following data (at least 5 of each data type): IP addresses, URLs, SHA-1 hashes, SHA-256 hashes, MD5 hashes, email addresses, domain names.

## Configure OnboardingIntegration in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Number of incidents to create per minute | False |
| Maximum number of incidents to create | False |
| How often to create new incidents (in minutes) | False |
| Fetch incidents | False |
| Incident type | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### demo-ip

***
Gets the simulated reputation of the IP address.

#### Base Command

`demo-ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | The IP address to get the reputation of. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IP.Address | String | IP address that was tested | 
| IP.Malicious.Vendor | String | For malicious IPs, the vendor that made the decision | 
| IP.Malicious.Description | String | For malicious IPs, the reason that the vendor made the decision | 
| DBotScore.Type | String | The indicator type | 
| DBotScore.Vendor | String | The vendor used to calculate the score | 
| DBotScore.Score | Number | The actual score | 
| DBotScore.Indicator | String | The indicator that was tested | 

### demo-url

***
Gets the simulated reputation of the URL address.

#### Base Command

`demo-url`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | The URL to get the reputation of. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| URL.Data | String | The URL address that was tested | 
| URL.Malicious.Vendor | String | For malicious URLs, the vendor that made the decision | 
| URL.Malicious.Description | String | For malicious URLs, the reason that the vendor made the decision | 
| DBotScore.Type | String | The indicator type | 
| DBotScore.Vendor | String | The vendor used to calculate the score | 
| DBotScore.Score | Number | The actual score | 
| DBotScore.Indicator | String | The indicator that was tested | 

### demo-domain

***
Gets the simulated reputation of the domain.

#### Base Command

`demo-domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The domain to get the reputation of. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | String | The domain name that was tested | 
| Domain.Malicious.Vendor | String | For malicious domains, the vendor that made the decision | 
| Domain.Malicious.Description | String | For malicious domains, the reason that the vendor made the decision | 
| DBotScore.Type | String | Indicator type | 
| DBotScore.Vendor | String | Vendor used to calculate the score | 
| DBotScore.Score | Number | The actual score | 
| DBotScore.Indicator | String | The indicator that was tested | 

### demo-file

***
Gets the simulated reputation of the file hash.

#### Base Command

`demo-file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | The file hash to get the reputation of. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.MD5 | String | File MD5 hash that was tested | 
| File.SHA1 | String | File SHA-1 hash that was tested | 
| File.SHA256 | String | File SHA-256 hash that was tested | 
| File.SHA512 | String | File SHA-512 hash that was tested | 
| File.Malicious.Vendor | String | For malicious files, the vendor that made the decision | 
| File.Malicious.Description | String | For malicious files, the reason that the vendor made the decision | 
| DBotScore.Type | String | The indicator type | 
| DBotScore.Vendor | String | The vendor used to calculate the score | 
| DBotScore.Score | Number | The actual score | 
| DBotScore.Indicator | String | The indicator that was tested | 

### demo-email

***
Gets the simulated reputation of the email address.

#### Base Command

`demo-email`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | The email address to get the reputation of. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Account.Email.Address | String | The email address that was tested | 
| Account.Email.Malicious.Vendor | String | For malicious email addresses, the vendor that made the decision | 
| Account.Email.Malicious.Description | String | For malicious email addresses, the reason that the vendor made the decision | 
| DBotScore.Type | String | The indicator type | 
| DBotScore.Vendor | String | The vendor used to calculate the score | 
| DBotScore.Score | Number | The actual score | 
| DBotScore.Indicator | String | The indicator that was tested | 
