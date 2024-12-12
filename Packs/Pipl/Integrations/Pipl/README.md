Pipl provides a reputation for email addresses and identity solutions.

## Configure Pipl in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server URL \(e.g., https://api.pipl.com/search/\) | True |
| key | API Key | False |
| credentials_api_key | API Key | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| Source Reliability | Reliability of the source providing the intelligence data. | False |


## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### pipl-search

***
Search for required query

#### Base Command

`pipl-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | Email address to search. | Optional | 
| phone | Home/work/mobile phone number to search. | Optional | 
| username | Username/screen-name to search. Minimum 4 characters. | Optional | 
| first-name | First name to search. Minimum 2 characters. | Optional | 
| last-name | Last name to search. Minimum 2 characters. | Optional | 
| middle-name | Middle name or middle initial to search. | Optional | 
| raw-name | Full name to search. Use this parameter if the accurate name parts (first/middle/last) are not available, this parameter will only be used in absence of first-name and last-name. | Optional | 
| country | A two-letter country code to searchs. | Optional | 
| state | A United States, Canada, Great Britain or Australia state code. If a US state is provided and no country specified, we’ll assume the country to be US. | Optional | 
| city | City to search. | Optional | 
| zipcode | ZIP code to search. | Optional | 
| raw-address | Full address to search. | Optional | 
| age | Age to search in String, an exact (YY) or approximate (YY-YY) age. | Optional | 
| columns | Order of columns to be displayed in results (comma seperated list of values). | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Account.Email.Address | unknown | Email addresses | 
| Account.IDs | unknown | User IDs | 
| Account.Addresses | unknown | Addresses \(geographic\) | 
| Account.Names | unknown | Full names | 
| Account.Phones | unknown | Phone numbers | 
| Account.Usernames | unknown | Online platforms usernames | 

### email

***
Searches for information regarding given email address

#### Base Command

`email`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | Email address to search for. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Account.Email.Address | unknown | Email addresses | 
| Account.IDs | unknown | User IDs | 
| Account.Addresses | unknown | Addresses \(geographic\) | 
| Account.Names | unknown | Full names | 
| Account.Phones | unknown | Phone numbers | 
| Account.Usernames | unknown | Online platforms usernames | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual DBot score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 