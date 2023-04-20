SEARCH_SAPM_ACCOUNTS_RESPONSE = {
    "searchResults": [{
        "changePeriod": 7,
        "comment": None,
        "configName": "Linux",
        "createdAt": 1649081886802,
        "dbId": 147636,
        "description": None,
        "deviceId": "bdabee8c-fd74-4989-9e00-e00ab88c45a8",
        "eventUserEid": "admin",
        "groupFullPath": "/Multi Level",
        "ip": "Device_IP_Address",
        "password": "gdh5esd",
        "permissions": [
            {
                "permission": "READ_ONLY",
                "userGroupEid": None,
                "userGroupId": "756caa17-3f0b-48b5-85a9-03a48d226731"
            }
        ],
        "secretName": "account7@Device_IP_Address",
        "secretNotes": None,
        "secretType": "DYNAMIC",
        "username": "account6"
    },
        {
            "changePeriod": 5,
            "comment": None,
            "configName": "Windows",
            "createdAt": 1856081886802,
            "dbId": 147637,
            "description": None,
            "deviceId": "bdbnfyst-ef56-4989-9e00-r56y88c45a8",
            "eventUserEid": "admin",
            "groupFullPath": "/Multi Level",
            "ip": "Device_IP_Address",
            "password": "sdf4te",
            "permissions": [
                {
                    "permission": "READ_ONLY",
                    "userGroupEid": None,
                    "userGroupId": "756caa17-3f0b-48b5-85a9-03a48d226731"
                }
            ],
            "secretName": "account7@Device_IP_Address",
            "secretNotes": None,
            "secretType": "DYNAMIC",
            "username": "account7"
        }]
}

EMPTY_SEARCH_SAPM_ACCOUNTS_RESPONSE = {
    "searchResults": []
}

GET_SAPM_USER_INFO_RESPONSE = [{
    "changePeriod": 7,
    "comment": None,
    "configName": "Linux",
    "createdAt": 1649081886802,
    "dbId": 147636,
    "description": None,
    "deviceId": "bdabee8c-fd74-4989-9e00-e00ab88c45a8",
    "eventUserEid": "admin",
    "groupFullPath": "/Multi Level",
    "ip": "Device_IP_Address",
    "password": "23refs",
    "permissions": [
        {
            "permission": "READ_ONLY",
            "userGroupEid": None,
            "userGroupId": "756caa17-3f0b-48b5-85a9-03a48d226731"
        }
    ],
    "secretName": "account6@Device_IP_Address",
    "secretNotes": None,
    "secretType": "DYNAMIC",
    "username": "account6"
}]

SHOW_PASSWORD_RESPONSE = {
    "password": "pass123",
    "passwordPart": "FULL",
    "secretNotes": "This is Oracle DB Privileged Account"
}

ERROR_MESSAGE_RESPONSE = 'This is an error message'
