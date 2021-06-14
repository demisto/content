full_report = {
   "Report_Entry": [{
      "Employment_Status": "Active",
      "Last_Day_Of_Work": "10/05/2035",
      "Last_Hire_Date": "10/05/2020",
      "Emp_ID": "100122_UPDATED",
      "Email_Address": "rrahardjo@paloaltonetworks.com"
   }]
}

mapped_workday_user = {
   "Employment Status": "Active",
   "Last Day of Work": "10/05/2035",
   "Hire Date": "10/05/2020",
   "Employee ID": "100122_UPDATED",
   "Username": "rrahardjo@paloaltonetworks.com",
   "Email": "rrahardjo@paloaltonetworks.com"
}

employee_id_to_user_profile = {
   "100122": {
      "employmentstatus": "Active",
      "lastdayofwork": "10/05/2035",
      "hiredate": "10/05/2020",
      "employeeid": "100122",
      "username": "rrahardjo@paloaltonetworks.com",
      "email": "rrahardjo@paloaltonetworks.com"
   }
}

email_to_user_profile = {
   "rrahardjo@paloaltonetworks.com": {
      "employmentstatus": "Active",
      "lastdayofwork": "10/05/2035",
      "hiredate": "10/05/2020",
      "employeeid": "100122",
      "username": "rrahardjo@paloaltonetworks.com",
      "email": "rrahardjo@paloaltonetworks.com"
   }
}


event_data = [
    {
        "name": "rrahardjo@paloaltonetworks.com",
        "rawJSON": "{\"Employment_Status\": \"Active\", \"Last_Day_Of_Work\": \"10/05/2035\", \"Last_Hire_Date\": \"10/05/2020\", \"Emp_ID\": \"100122_UPDATED\", \"Email_Address\": \"rrahardjo@paloaltonetworks.com\", \"UserProfile\": {\"employmentstatus\": \"Active\", \"lastdayofwork\": \"10/05/2035\", \"hiredate\": \"10/05/2020\", \"employeeid\": \"100122_UPDATED\", \"username\": \"rrahardjo@paloaltonetworks.com\", \"email\": \"rrahardjo@paloaltonetworks.com\"}}",
        "type": "IAM - Update User",
        "details": "The user has been updated:\nemployeeid field was updated to \"100122_UPDATED\"."
    }
]
