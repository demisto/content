The dark web scan integration notifies you if login credentials to your company are being sold on the dark web.

## Configure BechtleDarkWebScan in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| API Key | Your darkwebscan.app API Key | True |
| Additional request headers |  | False |
| Fetch incidents |  | False |
| Incidents Fetch Interval |  | False |
| First fetch time |  | False |
| Incident type |  | False |
| Maximum incidents per fetch |  | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### darkwebscan-getcompanies

***
Returns a list of all companies associated with your API key.

#### Base Command

`darkwebscan-getcompanies`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BechtleDarkWebScan.Companies | String | All companies that you have access to. |

### darkwebscan-getleaks

***
Returns leaked credentials for a given company_id.

#### Base Command

`darkwebscan-getleaks`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| company_id | ID of the company to retrieve leaked credentials for. | Required |
| only_new | Only return leaks not previously seen by this integration instance. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BechtleDarkWebScan.LeakedCredentials | String | Leaked credentials for a given company_id. |

### darkwebscan-getosint

***
Returns OSINT information about the associated domain of a given company_id.

#### Base Command

`darkwebscan-getosint`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| company_id | ID of the company to retrieve OSINT information for. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BechtleDarkWebScan.OSINT | String | OSINT information \(email addresses, subdomains, ...\) for the associated domain of a given company_id. |

### darkwebscan-getemailsecurity

***
Returns information about the email security for the associated domain of a given company_id.

#### Base Command

`darkwebscan-getemailsecurity`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| company_id | ID of the company to retrieve email security information for. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BechtleDarkWebScan.EmailSecurity | String | Email security \(SPF, DMARC, DANE, ...\) for the associated domain of a given company_id. |

### darkwebscan-getwaf

***
Returns Web Application Firewall Status information about the associated domain of a given company_id.

#### Base Command

`darkwebscan-getwaf`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| company_id | ID of the company to retrieve Web Application Firewall Status information for. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BechtleDarkWebScan.WAF | String | Web Application Firewall status and product name \(if applicable\) |

### darkwebscan-resetcontext

***
Resets integration context for the DarkWebScan. May result in many alerts reappearing.

#### Base Command

`darkwebscan-resetcontext`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BechtleDarkWebScan.ResetContext | String | Returns text whether the reset was successful or not. |
