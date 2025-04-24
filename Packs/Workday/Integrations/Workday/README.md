Workday offers enterprise-level software solutions for financial management, human resources, and planning.
This integration was integrated and tested with version 34.0 of Workday
## Configure Workday in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| base_url | Server URL \(e.g. https://example.net\) | True |
| username | Username | True |
| password | Password | True |
| tenant_name | Tenant name | True |
| token | Token | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
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
| count | The maximum number of results to return. (default = 50) | Optional | 
| page | The page from which to get the employees data. (default = 1) | Optional | 
| managers | Number of managers to show. (default = 3) | Optional | 


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
```!workday-list-workers employee_id=123456```
##### or
```!workday-list-workers page=1 count=1 managers=3```


#### Context Example
```
{
    "Workday": {
        "Worker": {
            "Active": "1",
            "Addresses": [
                {
                    "Address_ID": "ADDRESS_REFERENCE-3-3415",
                    "Country": "SA",
                    "Formatted_Address": "Kingdom Tower&#xa;P.O Box: 230 888, Floor 28&#xa;Offices 1431, 1435, 1428, 1429&#xa;Riyadh 11321&#xa;Riyadh&#xa;Saudi Arabia",
                    "Postal_Code": "112345",
                    "Region": "01",
                    "Region_Descriptor": "Riyadh",
                    "Type": "WORK"
                },
                {
                    "Address_ID": "ADDRESS_REFERENCE-6-107",
                    "Country": "SA",
                    "Formatted_Address": "King Faisal District&#xa;Riyadh 13215&#xa;Saudi Arabia",
                    "Postal_Code": "112345",
                    "Region": "",
                    "Region_Descriptor": "",
                    "Type": "HOME"
                }
            ],
            "Business_Site_Address": {
                "Address_ID": "ADDRESS_REFERENCE-3-3415",
                "Country": "SA",
                "Formatted_Address": "Kingdom Tower&#xa;P.O Box: 230 888, Floor 28&#xa;Offices 1431, 1435, 1428, 1429&#xa;Riyadh 11321&#xa;Riyadh&#xa;Saudi Arabia",
                "Postal_Code": "112345"
            },
            "Business_Site_Name": "Office - Saudi Arabia - Riyadh",
            "Business_Site_Type": "Office",
            "Business_Site_id": "3010",
            "Business_Title": "Regional Sales Manager",
            "Country": "AE",
            "Critical_Job": "0",
            "Days_Unemployed": "0",
            "Default_Weekly_Hours": "40",
            "Emails": [
                {
                    "Email_Address": "test@hotmail.com",
                    "Primary": true,
                    "Public": false,
                    "Type": "HOME"
                },
                {
                    "Email_Address": "test@paloaltonetworks.com",
                    "Primary": true,
                    "Public": true,
                    "Type": "WORK"
                }
            ],
            "End_Date": null,
            "End_Employment_Reason_Reference": "",
            "Exclude_from_Headcount": "0",
            "First_Day_of_Work": "2020-03-25",
            "Full_Time_Equivalent_Percentage": "100",
            "Has_International_Assignment": "0",
            "Hire_Date": "2020-03-25",
            "Hire_Reason": "Hire_Employee_Hire_Employee_Rehire",
            "Home_Country_Reference": "SA",
            "Job_Profile_Name": "Regional Sales Manager (DQC)",
            "Legal_First_Name": "Test_name",
            "Legal_Last_Name": "Test_last_name",
            "Managers": [
                {
                    "Manager_ID": "100002",
                    "Manager_Name": "manager_name_3"
                },
                {
                    "Manager_ID": "100001",
                    "Manager_Name": "manager_name_2"
                },
                {
                    "Manager_ID": "100000",
                    "Manager_Name": "manager_name_1"
                }
            ],
            "Pay_Rate_Type": "Salary",
            "Pay_Through_Date": null,
            "Phones": [
                {
                    "ID": "PHONE_REFERENCE-3-4210",
                    "Phone_Number": "5-5501-2343",
                    "Type": "Mobile",
                    "Usage": "WORK"
                },
                {
                    "ID": "PHONE_REFERENCE-3-14614",
                    "Phone_Number": "55501234",
                    "Type": "Mobile",
                    "Usage": "HOME"
                }
            ],
            "Photo": "image_in_base64",
            "Position_ID": "POS-114061",
            "Position_Time_Type": "Full_time",
            "Position_Title": "Regional Sales Manager",
            "Preferred_First_Name": "Test_name",
            "Preferred_Last_Name": "Test_last_name",
            "Rehire": "1",
            "Resignation_Date": "2018-06-14",
            "Retired": "0",
            "Scheduled_Weekly_Hours": "40",
            "Start_Date": "2020-03-25",
            "Terminated": "0",
            "User_ID": "test@paloaltonetworks.com",
            "Work_Shift_Required": "0",
            "Worker_ID": "123456",
            "Worker_Type": "Regular"
        }
    }
}
```

#### Human Readable Output

>### Workers
>|Worker_ID|User_ID|Country|Preferred_First_Name|Preferred_Last_Name|Active|Position_Title|Business_Title|Start_Date|Terminated|
>|---|---|---|---|---|---|---|---|---|---|
>| 123456 | test@paloaltonetworks.com | AE | Test_name | Test_last_name | 1 | Regional Sales Manager | Regional Sales Manager | 2020-03-25 | 0 |