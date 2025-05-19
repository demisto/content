Use the Workday IAM Integration as part of the IAM premium pack.
For more information, please refer to the [Identity Lifecycle Management article](https://xsoar.pan.dev/docs/reference/articles/identity-lifecycle-management).

## Configure Workday IAM in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Username |  | False |
| Password |  | False |
| Workday Report URL |  | True |
| Fetch Limit (Recommended less than 200) |  | False |
| Fetch incidents | Whether or not to fetch events from Workday report. Enable only when all required configurations are set properly. | False |
| Incident type |  | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Mapper (incoming) | Used to map Workday report entries to XSOAR indicators format. | False |
| Sync user profiles on first run | If checked, the first fetch won't trigger incidents but all of the User Profile indicators will be created. | False |
| Fetch Samples | If checked, the fetch incidents command will sample \(at most\) five incidents. Use only to sample incidents for classification &amp;amp; mapping. | False |
| Date Format in Workday Report |  | False |
| Deactivation date field | Select the field that determines when to trigger a termination incident for deactivated employees. | False |
| Number of days before hire date to sync hires | Determines when employees are synced from Workday, i.e., when are the User Profile in XSOAR, and the users in the applications, created. Set to 0 to sync hires on their hire date. Leave empty to sync the hires immediately. | False |
| Number of days before hire date to enable Active Directory account | Determines when to enable the Active Directory accounts of employees. Set to 0 to enable the Active Directory accounts on their hire date. Leave empty to enable the accounts immediately. Note that this is effective only when the employees are already synced to XSOAR, so you should set a number lower, or equal to, the value in the \*Number of days before hire date to sync hires\* parameter. | False |
| Source Priority Level | Events will be fetched only for User Profiles with a Source Priority value less than or equal to the value of this parameter. | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### workday-iam-get-full-report
***
Gets the report entries from Workday.


#### Base Command

`workday-iam-get-full-report`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WorkdayIAM.ReportEntry.email | String | Email address of the employee in Workday. | 
| WorkdayIAM.ReportEntry.employeeid | String | Employee ID in Workday. | 
| WorkdayIAM.ReportEntry.username | String | Username of the employee in Workday. | 
| WorkdayIAM.ReportEntry.displayname | String | Display name of the employee. | 
| WorkdayIAM.ReportEntry.locationregion | String | Location of the employee in Workday. | 


#### Command Example
``` !workday-iam-get-full-report ```

#### Human Readable Output
### Results
|city|costcenter|costcentercode|countryname|department|displayname|email|employeeid|employeetype|employmentstatus|givenname|hiredate|jobcode|jobfamily|jobfunction|lastdayofwork|leadership|location|locationregion|manageremailaddress|personalemail|prehireflag|rehiredemployee|sourceoftruth|sourcepriority|state|streetaddress|surname|terminationdate|title|username|zipcode|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Santa Clara | Channel Sales | 120100 | United States Of America | Sales NAM:NAM Channel Sales | Ronny Rahardjo | rrahardjo@test.com | 100122 | Regular |  | Ronny | 03/25/2021 | 2245 | Product Management | Product Management Function | 02/15/2032 | Yes-HQ | Office - USA - CA - Headquarters | Americas | test@test.com | ronnyrahardjo@test.com | True | Yes | Workday IAM | 1 | California | 3000 Tannery Way | Rahardjo | 02/15/2032 | Dir, Product Line Manager | rrahardjo@test.com | 95054 |
| San Francisco | Magnifier Sales Inc | 101100 | United States Of America | WW Sales Functions:Cortex Sales | Stephen Arnold | sarnold@test.com | 101351 | Regular |  | Stephen | 03/26/2021 | 2163 | Software Engineering | Engineering Function | 02/15/2032 | No | Office - USA - CA - San Francisco | Americas | test@test.com | stevearnoldtstc@test.com | True | Yes | Workday IAM | 1 | California | WeWork Embarcadero Center | Arnold | 02/15/2032 | Mgr, SW Engineering | sarnold@test.com | 94111 |
