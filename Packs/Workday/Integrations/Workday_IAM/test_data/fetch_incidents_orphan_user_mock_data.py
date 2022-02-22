import json

full_report = {
    "Report_Entry": []
}

user_emails = ['test@paloaltonetworks.com']

email_to_user_profile = {
    "rrahardjo@paloaltonetworks.com": {
        "employmentstatus": "Active",
        "lastdayofwork": "10/05/2035",
        "hiredate": "10/05/2020",
        "employeeid": "100122",
        "username": "rrahardjo@paloaltonetworks.com",
        "email": "rrahardjo@paloaltonetworks.com",
        "sourcepriority": 1,
        "sourceoftruth": "Workday",
        "isprocessed": False
    }
}

event_data = [
    {
        "name": "rrahardjo@paloaltonetworks.com",
        "rawJSON": json.dumps({
            "Email_Address": "rrahardjo@paloaltonetworks.com",
            "UserProfile": json.dumps({
                "employmentstatus": "Terminated",
                "lastdayofwork": "10/05/2035",
                "hiredate": "10/05/2020",
                "employeeid": "100122",
                "username": "rrahardjo@paloaltonetworks.com",
                "email": "rrahardjo@paloaltonetworks.com",
                "sourcepriority": 1,
                "sourceoftruth": "Workday",
                "isprocessed": False
            }),
            "Emp_ID": "100122",
            "terminationtrigger": "Orphan"
        }),
        "type": "IAM - Terminate User",
        "details": "An orphan user was detected (could not find the user in Workday report). Please review and terminate if necessary."
    }
]
