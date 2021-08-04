full_report = {
   "Report_Entry": [{
      "Employment_Status": "Active",
      "Last_Day_Of_Work": "10/05/2035",
      "Last_Hire_Date": "10/05/2020",
      "Emp_ID": "100122",
      "Email_Address": "rrahardjo_UPDATED@paloaltonetworks.com",
   }]
}

mapped_workday_user = {
   "Employment Status": "Active",
   "Last Day of Work": "10/05/2035",
   "Hire Date": "10/05/2020",
   "Employee ID": "100122",
   "Username": "rrahardjo_UPDATED@paloaltonetworks.com",
   "Email": "rrahardjo_UPDATED@paloaltonetworks.com",
   "Source Priority": 1,
   "Source of Truth": "Workday IAM"
}

employee_id_to_user_profile = {
   "100122": {
      "employmentstatus": "Active",
      "lastdayofwork": "10/05/2035",
      "hiredate": "10/05/2020",
      "employeeid": "100122",
      "username": "rrahardjo@paloaltonetworks.com",
      "email": "rrahardjo@paloaltonetworks.com",
      "sourcepriority": 1,
      "sourceoftruth": "Workday IAM"
   }
}

email_to_user_profile = {
   "rrahardjo@paloaltonetworks.com": {
      "employmentstatus": "Active",
      "lastdayofwork": "10/05/2035",
      "hiredate": "10/05/2020",
      "employeeid": "100122",
      "username": "rrahardjo@paloaltonetworks.com",
      "email": "rrahardjo@paloaltonetworks.com",
      "sourcepriority": 1,
      "sourceoftruth": "Workday IAM"
   }
}

event_data = [
    {
        "name": "rrahardjo_UPDATED@paloaltonetworks.com",
        "rawJSON": "{\"Employment_Status\": \"Active\", \"Last_Day_Of_Work\": \"10/05/2035\", \"Last_Hire_Date\": \"10/05/2020\", \"Emp_ID\": \"100122\", \"Email_Address\": \"rrahardjo_UPDATED@paloaltonetworks.com\", \"UserProfile\": {\"employmentstatus\": \"Active\", \"lastdayofwork\": \"10/05/2035\", \"hiredate\": \"10/05/2020\", \"employeeid\": \"100122\", \"username\": \"rrahardjo_UPDATED@paloaltonetworks.com\", \"email\": \"rrahardjo_UPDATED@paloaltonetworks.com\", \"sourcepriority\": 1, \"sourceoftruth\": \"Workday IAM\", \"olduserdata\": {\"employmentstatus\": \"Active\", \"lastdayofwork\": \"10/05/2035\", \"hiredate\": \"10/05/2020\", \"employeeid\": \"100122\", \"username\": \"rrahardjo@paloaltonetworks.com\", \"email\": \"rrahardjo@paloaltonetworks.com\", \"sourcepriority\": 1, \"sourceoftruth\": \"Workday IAM\"}}}",
        "type": "IAM - Update User",
        "details": "The user has been updated:\n"
                   "username field was updated to \"rrahardjo_UPDATED@paloaltonetworks.com\".\n"
                   "email field was updated to \"rrahardjo_UPDATED@paloaltonetworks.com\"."
    }
]
