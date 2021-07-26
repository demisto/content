full_report = {
    "Report_Entry": [
        {
            "Employment_Status": "Active",
            "Last_Day_Of_Work": "10/05/2035",
            "Last_Hire_Date": "10/05/2020",
            "Emp_ID": "100123",
            "Display_Name": "Rony Rahardjo",
            "Email_Address": "rarahardjo@paloaltonetworks.com"
        }
    ]
}

employee_id_to_user_profile = {
    "100122": {
        "employmentstatus": "Active",
        "lastdayofwork": "10/05/2035",
        "hiredate": "10/05/2020",
        "employeeid": "100122",
        "displayname": "Rony Rahardjo",
        "username": "rrahardjo@paloaltonetworks.com",
        "email": "rrahardjo@paloaltonetworks.com",
        "sourcepriority": 1,
        "sourceoftruth": "Workday IAM",
        "isprocessed": False
    }
}

email_to_user_profile = {
   "rrahardjo@paloaltonetworks.com": {
       "employmentstatus": "Active",
       "lastdayofwork": "10/05/2035",
       "hiredate": "10/05/2020",
       "employeeid": "100122",
       "displayname": "Rony Rahardjo",
       "username": "rrahardjo@paloaltonetworks.com",
       "email": "rrahardjo@paloaltonetworks.com",
       "sourcepriority": 1,
       "sourceoftruth": "Workday IAM",
       "isprocessed": False
   }
}

display_name_to_user_profile = {
    "Rony Rahardjo": [{
        "employmentstatus": "Active",
        "lastdayofwork": "10/05/2035",
        "hiredate": "10/05/2020",
        "employeeid": "100122",
        "displayname": "Rony Rahardjo",
        "username": "rrahardjo@paloaltonetworks.com",
        "email": "rrahardjo@paloaltonetworks.com",
        "sourcepriority": 1,
        "sourceoftruth": "Workday IAM",
        "isprocessed": False
    }]
}

mapped_workday_user = {
    "Employment Status": "Active",
    "Last Day of Work": "10/05/2035",
    "Hire Date": "10/05/2020",
    "Employee ID": "100123",
    "Display Name": "Rony Rahardjo",
    "Username": "rarahardjo@paloaltonetworks.com",
    "Email": "rarahardjo@paloaltonetworks.com",
    "Source Priority": 1,
    "Source of Truth": "Workday IAM"
}

event_data = [
    {
        "name": "rarahardjo@paloaltonetworks.com",
        "type": "IAM - Sync User",
        "rawJSON": "{\"Employment_Status\": \"Active\", \"Last_Day_Of_Work\": \"10/05/2035\", \"Last_Hire_Date\": \"10/05/2020\", \"Emp_ID\": \"100123\", \"Display_Name\": \"Rony Rahardjo\", \"Email_Address\": \"rarahardjo@paloaltonetworks.com\", \"UserProfile\": {\"employmentstatus\": \"Active\", \"lastdayofwork\": \"10/05/2035\", \"hiredate\": \"10/05/2020\", \"employeeid\": \"100123\", \"displayname\": \"Rony Rahardjo\", \"username\": \"rarahardjo@paloaltonetworks.com\", \"email\": \"rarahardjo@paloaltonetworks.com\", \"sourcepriority\": 1, \"sourceoftruth\": \"Workday IAM\"}}",
        "details": "Detected an \"IAM - New Hire\" event, but display name already exists. Please review."
    }
]
