full_report = {
   "Report_Entry": []
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
      "sourceoftruth": "Workday IAM",
      "isprocessed": False
   }
}


event_data = [
    {
        "name": "rrahardjo@paloaltonetworks.com",
        "rawJSON": "{\"Email_Address\": \"rrahardjo@paloaltonetworks.com\", \"UserProfile\": {\"employmentstatus\": \"Terminated\", \"lastdayofwork\": \"10/05/2035\", \"hiredate\": \"10/05/2020\", \"employeeid\": \"100122\", \"username\": \"rrahardjo@paloaltonetworks.com\", \"email\": \"rrahardjo@paloaltonetworks.com\", \"sourcepriority\": 1, \"sourceoftruth\": \"Workday IAM\", \"isprocessed\": false}, \"Emp_ID\": \"100122\"}",
        "type": "IAM - Sync User",
        "details": "An orphan user was detected (could not find the user in Workday report). Please review and terminate if necessary."
    }
]
