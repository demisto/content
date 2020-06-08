EXPECTED_SEARCH_EVENTS = {
    'Zimperium.Users(val.objectId === obj.objectId)':
        [
            {'eventId': 'c4220bdf-0c0b-489c-a915-7d71bba7197a', 'eventStateCode': 1, 'eventState': 'Pending',
             'typeDesc': 'ZIPS_EVENT', 'eventVector': '2', 'severity': 'IMPORTANT', 'eventName': 'THREAT_DETECTED',
             'eventFullName': 'host.vulnerable.ios', 'customerId': 'becky', 'customerContactName': 'becky',
             'customerContactPhone': '+1 415 1234567',
             'deviceHash': 'ae14a9f3359cc75f122c4b38f0a033503b82995e5ec4fe54d5a93df35f9b81',
             'deviceId': '37245C48-D3B9-474A-80BA-54E66DDF0D94', 'mdmId': None,
             'zdid': '0082956f-380c-4e91-baf6-6e36da54040a',
             'latitude': 32.925141094962385, 'longitude': -96.84469371892781, 'bssid': 'Unknown', 'ssid': 'Unknown',
             'deviceTime': '2019-01-08 18:39:56 +0000', 'queuedTime': '2019-01-08 18:39:56 +0000',
             'persistedTime': '2019-01-08 18:39:56 +0000', 'lastSeenTime': '2019-01-08 18:39:55 +0000',
             'mitigatedDate': None,
             'deviceModel': 'iPhone', 'osType': 'iOS', 'osVersion': '11.4.1', 'country': 'US',
             'userEmail': 'pat@example.com',
             'userPhoneNumber': '', 'firstName': 'anonymous', 'middleName': None, 'lastName': 'user',
             'locationDetail': {'previousLongitude': -96.84469371892781, 'previousLatitude': 32.925141094962385,
                                'exact': True,
                                'previousSampledTimeAsDate': 1546972781000, 'sampledTimeAsDate': 1546972796046},
             'bundleId': 'com.zimperium.zIPS.appstore', 'zipsVersion': '4.7.0', 'appName': 'zIPS', 'tag1': '',
             'tag2': '',
             'incidentSummary': 'The system has detected that the iOS version installed onyour device is not '
                                'up-to-date. The outdated operating system exposes the device to known vulnerabilities '
                                'and the threat of being exploited by malicious actors. It is advised to update your '
                                'operating system immediately.',
             'eventDetail': None},
            {'eventId': '8065749b-c12c-4ba5-995c-7efaa3eef254', 'eventStateCode': 1, 'eventState': 'Pending',
             'typeDesc': 'ZIPS_EVENT', 'eventVector': '2', 'severity': 'IMPORTANT', 'eventName': 'THREAT_DETECTED',
             'eventFullName': 'host.pin', 'customerId': 'becky', 'customerContactName': 'becky',
             'customerContactPhone': '+1 415 1234567',
             'deviceHash': 'ae14a9f3359cc75f122c4b38f0a033503b82995e5ec4fe54d5a93df35f9b81',
             'deviceId': '37245C48-D3B9-474A-80BA-54E66DDF0D94', 'mdmId': None,
             'zdid': '0082956f-380c-4e91-baf6-6e36da54040a',
             'latitude': 32.925141094962385, 'longitude': -96.84469371892781, 'bssid': '9c:5d:12:fa:b7:27',
             'ssid': 'z-Wifi',
             'deviceTime': '2019-01-08 18:39:43 +0000', 'queuedTime': '2019-01-08 18:39:43 +0000',
             'persistedTime': '2019-01-08 18:39:43 +0000', 'lastSeenTime': '2019-01-08 18:39:55 +0000',
             'mitigatedDate': None,
             'deviceModel': 'iPhone', 'osType': 'iOS', 'osVersion': '11.4.1', 'country': 'US',
             'userEmail': 'pat@example.com',
             'userPhoneNumber': '', 'firstName': 'Test', 'middleName': None, 'lastName': 'User',
             'locationDetail': {'previousLongitude': 0, 'previousLatitude': 0, 'exact': None,
                                'sampledTimeAsDate': 1546972783751}, 'bundleId': 'com.zimperium.zIPS.appstore',
             'zipsVersion': '4.7.0', 'appName': 'zIPS', 'tag1': '', 'tag2': '',
             'incidentSummary': 'Your device is not setup to use a PIN code, Password, or Pattern to lock your device. '
                                'By not using a PIN code, Password, or Pattern to lock your device, sensitive data on '
                                'the device could be exposed to attackers if your device is stolen or compromised. '
                                'It is advised that a PIN code, Password, or Pattern be enabled as a standard security '
                                'practice in securing your device and securing the sensitive data on the device.',
             'eventDetail': None}
        ]
}
EXPECTED_SEARCH_USERS = {
    'Zimperium.Users(val.objectId === obj.objectId)':
        [
            {
                'objectId': '1B9182C7-8C12-4499-ADF0-A338DEFDFC33', 'lastLogin': '2019-02-01T17:12:35+0000',
                'email': 'zauto@example.com', 'alias': 'e7f4eb20-5433-42e0-8229-8910e342d4fc', 'firstName': 'zAuto',
                'middleName': 'Tool', 'lastName': 'QA', 'status': 1, 'dateJoined': '2019-02-01T17:12:35+0000',
                'agreedToTerms': True, 'pwdRecoveryRequest': False, 'role': 4, 'signupSteps': 1,
                'createdDate': '2019-02-01T17:12:35+0000', 'modifiedDate': '2019-02-01T17:12:35+0000',
                'roles': [{'roleId': 150061}],
                'activationTokenUrl': 'https://demo-device-api.zimperium.com/activation?stoken\\...redirect_uri=zips',
                'superuser': False, 'staff': False, 'phoneNumberVerified': False, 'syncedFromMdm': False
            }
        ]
}
EXPECTED_USER_GET_BY_ID = {
    'Zimperium.Users(val.objectId === obj.objectId)':
        {
            "objectId": "1B9182C7-8C12-4499-ADF0-A338DEFDFC33",
            "lastLogin": "2019-02-01T17:12:35+0000",
            "email": "zauto@example.com",
            "alias": "e7f4eb20-5433-42e0-8229-8910e342d4fc",
            "firstName": "zAuto",
            "middleName": "Tool",
            "lastName": "QA",
            "status": 1,
            "dateJoined": "2019-02-01T17:12:35+0000",
            "agreedToTerms": True,
            "pwdRecoveryRequest": False,
            "role": 4,
            "signupSteps": 1,
            "createdDate": "2019-02-01T17:12:35+0000",
            "modifiedDate": "2019-02-01T17:12:35+0000",
            "roles": [
                {
                    "roleId": 150061
                }
            ],
            "activationTokenUrl": "https://demo-device-api.zimperium.com",
            "superuser": False,
            "staff": False,
            "phoneNumberVerified": False,
            "syncedFromMdm": False
        }
}
