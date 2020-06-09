Workday offers enterprise-level software solutions for financial management, human resources, and planning.
This integration was integrated and tested with version xx of Workday
## Configure Workday on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Workday.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| base_url | Server URL \(e.g. https://example.net\) | True |
| username | Username | True |
| password | Password | True |
| tenant_name | Tenant name | True |
| token | Token | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### workday-list-workers
***
List workers command - Returns information for specified workers.


#### Base Command

`workday-list-workers`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| employee_id | Employee ID of the worker for which to get information. | Optional | 
| count | The maximum number of results to return. | Optional | 
| page | The page from which to get the employees data. | Optional | 
| managers | Number of managers to show. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Workday.Worker.Worker_ID | String | The ID for the employee or contingent worker. | 
| Workday.Worker.User_ID | String | Text attribute identifying User Name. | 
| Workday.Worker.Country | String | The worker Country. | 
| Workday.Worker.Legal_First_Name | String | The First Name \(Given Name\) for a worker. | 
| Workday.Worker.Legal_Last_Name | String | The Last Name \(Family Name\) for a worker. | 
| Workday.Worker.Preferred_First_Name | String | The First Name \(Preferred Name\) for a worker. | 
| Workday.Worker.Preferred_Last_Name | String | The Last Name \(Preferred Name\) for a worker. | 
| Workday.Worker.Position_ID | String | Text attribute identifying Position ID. | 
| Workday.Worker.Position_Title | String | Text attribute identifying Position Title. | 
| Workday.Worker.Business_Title | String | Business title for the position. | 
| Workday.Worker.Start_Date | String | Date the Worker first started work in this Position. | 
| Workday.Worker.End_Employment_Reason_Reference | String | Termination/End Additional Job Reason. | 
| Workday.Worker.Worker_Type | String | The worker type for the position. | 
| Workday.Worker.Position_Time_Type | String | Position time type. | 
| Workday.Worker.Scheduled_Weekly_Hours | String | Scheduled Weekly Hours for Position. | 
| Workday.Worker.Default_Weekly_Hours | String | Standard Weekly Hours for Position. | 
| Workday.Worker.Full_Time_Equivalent_Percentage | String | Full Time Equivalent Percentage for Position. | 
| Workday.Worker.Exclude_from_Headcount | String | If Y, the position will be excluded from headcount reporting. | 
| Workday.Worker.Pay_Rate_Type | String | Pay rate type for the position. | 
| Workday.Worker.Job_Profile_Name | String | The name of the job profile. | 
| Workday.Worker.Work_Shift_Required | String | Returns true if a work shift is required on the position where this job profile is used. | 
| Workday.Worker.Critical_Job | String | Returns true if the job profile is considered a critical job. | 
| Workday.Worker.Business_Site_id | String | Business Site ID. | 
| Workday.Worker.Business_Site_Name | String | The name of the location. | 
| Workday.Worker.Business_Site_Type | String | The type of a location. | 
| Workday.Worker.Business_Site_Address.Address_ID | String | Business site address ID. | 
| Workday.Worker.Business_Site_Address.Formatted_Address | String | The formatted address in the format specified for the country. | 
| Workday.Worker.Business_Site_Address.Country | String | Country for the address. | 
| Workday.Worker.Business_Site_Address.Postal_Code | String | The postal code part of the address. | 
| Workday.Worker.End_Date | String | The effective date of the end employment business process. | 
| Workday.Worker.Pay_Through_Date | String | The pay through date for the end of employment. | 
| Workday.Worker.Active | String | Boolean attribute identifying whether the Worker is Active. | 
| Workday.Worker.Hire_Date | String | The most recent hire date for the employee or contract start date for the contingent worker. | 
| Workday.Worker.Hire_Reason | String | Reason for Hire from the most recent Hire event. | 
| Workday.Worker.First_Day_of_Work | String | First Day of Work only applies to the Payroll web service. | 
| Workday.Worker.Retired | String | Boolean attribute identifying whether the Worker is currently retired. | 
| Workday.Worker.Days_Unemployed | String | Number of days unemployed since the employee first joined the work force. Used only for China. | 
| Workday.Worker.Terminated | String | Boolean attribute identifying whether the Worker is currently Terminated. | 
| Workday.Worker.Termination_Date | String | Most recent Termination Date. | 
| Workday.Worker.Primary_Termination_Reason | String | The primary reason for the worker's most recent termination. | 
| Workday.Worker.Primary_Termination_Category | String | Reference to primary termination reason category. | 
| Workday.Worker.Termination_Involuntary | String | Indicates if the termination was involuntary. | 
| Workday.Worker.Rehire | String | Returns "Yes" if the worker is a rehire based on the most recent hire event. | 
| Workday.Worker.Termination_Last_Day_of_Work | String | Last day worked for the worker's termination event. | 
| Workday.Worker.Resignation_Date | String | Date the employee submitted their resignation. | 
| Workday.Worker.Has_International_Assignment | String | Indicates whether the worker has internaitonal assignment | 
| Workday.Worker.Home_Country_Reference | String | Contains the home country for worker's primary job \(ISO\_3166\-1\_Alpha\-2\_Code\). | 
| Workday.Worker.Photo | String | Worker's photo in base64. | 
| Workday.Worker.Addresses.Address_ID | String | Worker's address ID. | 
| Workday.Worker.Addresses.Formatted_Address | String | the formatted address in the format specified for the country. | 
| Workday.Worker.Addresses.Country | String | Country for the Worker's address. | 
| Workday.Worker.Addresses.Region | String | The ID of the region \(ISO\_3166\-2\_Code\) | 
| Workday.Worker.Addresses.Region_Descriptor | String | The region part of the address. Typically this contains the state/province information. | 
| Workday.Worker.Addresses.Postal_Code | String | The postal code part of the address. | 
| Workday.Worker.Addresses.Type | String | Address type. | 
| Workday.Worker.Emails.Email_Address | String | Email Address Information. | 
| Workday.Worker.Emails.Type | String | Usage type. | 
| Workday.Worker.Emails.Primary | String | Indicates if the communication method is primary. | 
| Workday.Worker.Emails.Public | String | Indicates if the Email is public. | 
| Workday.Worker.Phones.ID | String | Phone ID. | 
| Workday.Worker.Phones.Phone_Number | String | Phone number. | 
| Workday.Worker.Phones.Type | String | Phone Device Type. | 
| Workday.Worker.Phones.Usage | String | Phone usage data. | 
| Workday.Worker.Manager.Manager_ID | String | The manager worker ID. | 
| Workday.Worker.Manager.Manager_Name | String | The manager name. | 


#### Command Example
``` ```

#### Human Readable Output


