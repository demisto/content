This integration allows you to check if your personal information such as your email, username, or password is being compromised.

## Configure DeHashed in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| API Key | For generating an API Key, see https://www.dehashed.com. | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Email Severity: The DBot reputation for compromised emails (SUSPICIOUS or MALICIOUS) |  | False |
| Source Reliability | Reliability of the source providing the intelligence data. | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### dehashed-search

***
Performs a search to check if information is compromised.

#### Base Command

`dehashed-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_type | If you select the "all fields" option, the search is performed on all fields with the specified value entered in the "value" argument, and you don't have to pass the "operation" argument. Possible values are: email, ip_address, username, hashed_password, name, vin, address, phone, all_fields. | Required |
| value | The searched value. | Required |
| operation | The search operator. Possible values are: is, contains, regex. | Required |
| page | The number of page to return. Each page contains 1,000 results. | Optional |
| results_from | Starting result number to display. Default is 1. | Optional |
| results_to | Ending result number to display. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DeHashed.Search.Id | String | ID of the object. |
| DeHashed.Search.Email | String | Email address of the object. |
| DeHashed.Search.Username | String | Username of the object. |
| DeHashed.Search.Password | String | Password of the object. |
| DeHashed.Search.HashedPassword | String | Hashed password of the object. |
| DeHashed.Search.Name | String | Name of the object. |
| DeHashed.Search.Address | String | Address of the object. |
| DeHashed.Search.IpAddress | String | IP address of the object. |
| DeHashed.Search.Phone | Number | Phone number of the object. |
| DeHashed.Search.Dob | String | Date of birth. |
| DeHashed.Search.LicensePlate | String | License plate. |
| DeHashed.Search.Company | String | Company name. |
| DeHashed.Search.Url | String | Associated URL. |
| DeHashed.Search.Social | String | Social media handle. |
| DeHashed.Search.CryptocurrencyAddress | String | Cryptocurrency address. |
| DeHashed.Search.DatabaseName | String | Source database/breach name \(drives DBot score\). |
| Dehashed.LastQuery.ResultsFrom | Number | The value of the "results_from" argument that was passed in the last query. |
| Dehashed.LastQuery.ResultsTo | Unknown | The value of the "results_to" argument that was passed in the last query. |
| Dehashed.LastQuery.TotalResults | Number | The total number of entries returned from the last query. |
| Dehashed.LastQuery.DisplayedResults | Number | The number of entries that were displayed in Cortex XSOAR from the last query. |

#### Command Example

`!dehashed-search asset_type=all_fields operation=contains value=or-gal@gmail.com results_to=4 results_from=1`
`!dehashed-search asset_type=email operation=is value=or-gal@gmail.com page=1`
`!dehashed-search asset_type=name operation=contains value=gal,gil,test1 results_from=2 results_to=30 page=3`
`!dehashed-search asset_type=name operation=regex value=joh?n(ath[oa]n)`

#### Human Readable Output

### email

***
Checks if an email address was compromised.

#### Base Command

`email`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | The email address to check. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DeHashed.Search.Id | String | ID of the object. |
| DeHashed.Search.Email | String | Email address of the object. |
| DeHashed.Search.Username | String | Username of the object. |
| DeHashed.Search.Password | String | Password of the object. |
| DeHashed.Search.HashedPassword | String | Hashed password of the object. |
| DeHashed.Search.Name | String | Name of the object. |
| DeHashed.Search.Address | String | Address of the object. |
| DeHashed.Search.IpAddress | String | IP address of the object. |
| DeHashed.Search.Phone | Number | Phone number of the object. |
| DeHashed.Search.Dob | String | Date of birth. |
| DeHashed.Search.LicensePlate | String | License plate. |
| DeHashed.Search.Company | String | Company name. |
| DeHashed.Search.Url | String | Associated URL. |
| DeHashed.Search.Social | String | Social media handle. |
| DeHashed.Search.CryptocurrencyAddress | String | Cryptocurrency address. |
| DeHashed.Search.DatabaseName | String | Source database/breach name \(drives DBot score\). |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. |

#### Command Example

`!email email=or-gal@gmail.com`

#### Human Readable Output
