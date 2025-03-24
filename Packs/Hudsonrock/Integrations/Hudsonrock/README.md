# HYAS Insight

Integration with Hudsonrock OSINT tools to check IP, Email or username usage.

## Configure HYASInsight in Cortex


| **Parameter** | **Required** |
| --- |--------------|
| url | True         |
| Trust any certificate (not secure) | False        |
| Use system proxy settings | False        |
| integrationReliability | True         |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### ip

***
Send IP reputation query.

#### Base Command

`ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | List of IPs. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Hudsonrock.IP | string | IP reputation. | 
| IP.Address | String | IP address. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 

### email

***
Send Email reputation query.

#### Base Command

`email`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | List of emails. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Hudsonrock.Email | string | Email reputation. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 

### hudsonrock-get-username

***
Send username reputation query.

#### Base Command

`hudsonrock-get-username`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username to query. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Hudsonrock.Username | string | Username reputation. | 
