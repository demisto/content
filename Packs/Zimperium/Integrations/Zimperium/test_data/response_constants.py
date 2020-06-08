RESPONSE_SEARCH_EVENTS = {
    "content": [

        {
            "eventId": "c4220bdf-0c0b-489c-a915-7d71bba7197a",
            "eventStateCode": 1,
            "eventState": "Pending",
            "typeDesc": "ZIPS_EVENT",
            "eventVector": "2",
            "severity": "IMPORTANT",
            "eventName": "THREAT_DETECTED",
            "eventFullName": "host.vulnerable.ios",
            "customerId": "becky",
            "customerContactName": "becky",
            "customerContactPhone": "+1 415 1234567",
            "deviceHash": "ae14a9f3359cc75f122c4b38f0a033503b82995e5ec4fe54d5a93df35f9b81",
            "deviceId": "37245C48-D3B9-474A-80BA-54E66DDF0D94",
            "mdmId": None,
            "zdid": "0082956f-380c-4e91-baf6-6e36da54040a",
            "latitude": 32.925141094962385,
            "longitude": -96.84469371892781,
            "bssid": "Unknown",
            "ssid": "Unknown",
            "deviceTime": "2019-01-08 18:39:56 +0000",
            "queuedTime": "2019-01-08 18:39:56 +0000",
            "persistedTime": "2019-01-08 18:39:56 +0000",
            "lastSeenTime": "2019-01-08 18:39:55 +0000",
            "mitigatedDate": None,
            "deviceModel": "iPhone",
            "osType": "iOS",
            "osVersion": "11.4.1",
            "country": "US",
            "userEmail": "pat@example.com",
            "userPhoneNumber": "",
            "firstName": "anonymous",
            "middleName": None,
            "lastName": "user",
            "locationDetail": {
                "previousLongitude": -96.84469371892781,
                "previousLatitude": 32.925141094962385,
                "exact": True,
                "previousSampledTimeAsDate": 1546972781000,
                "sampledTimeAsDate": 1546972796046
            },
            "bundleId": "com.zimperium.zIPS.appstore",
            "zipsVersion": "4.7.0",
            "appName": "zIPS",
            "tag1": "",
            "tag2": "",
            "incidentSummary": "The system has detected that the iOS version installed onyour device is not up-to-date. "
                               "The outdated operating system exposes the device to known vulnerabilities and the threat of being"
                               " exploited by malicious actors. It is advised to update your operating system immediately.",
            "eventDetail": None
        },
        {
            "eventId": "8065749b-c12c-4ba5-995c-7efaa3eef254",
            "eventStateCode": 1,
            "eventState": "Pending",
            "typeDesc": "ZIPS_EVENT",
            "eventVector": "2",
            "severity": "IMPORTANT",
            "eventName": "THREAT_DETECTED",
            "eventFullName": "host.pin",
            "customerId": "becky",
            "customerContactName": "becky",
            "customerContactPhone": "+1 415 1234567",
            "deviceHash": "ae14a9f3359cc75f122c4b38f0a033503b82995e5ec4fe54d5a93df35f9b81",
            "deviceId": "37245C48-D3B9-474A-80BA-54E66DDF0D94",
            "mdmId": None,
            "zdid": "0082956f-380c-4e91-baf6-6e36da54040a",
            "latitude": 32.925141094962385,
            "longitude": -96.84469371892781,
            "bssid": "9c:5d:12:fa:b7:27",
            "ssid": "z-Wifi",
            "deviceTime": "2019-01-08 18:39:43 +0000",
            "queuedTime": "2019-01-08 18:39:43 +0000",
            "persistedTime": "2019-01-08 18:39:43 +0000",
            "lastSeenTime": "2019-01-08 18:39:55 +0000",
            "mitigatedDate": None,
            "deviceModel": "iPhone",
            "osType": "iOS",
            "osVersion": "11.4.1",
            "country": "US",
            "userEmail": "pat@example.com",
            "userPhoneNumber": "",
            "firstName": "Test",
            "middleName": None,
            "lastName": "User",
            "locationDetail": {
                "previousLongitude": 0,
                "previousLatitude": 0,
                "exact": None,
                "sampledTimeAsDate": 1546972783751
            },
            "bundleId": "com.zimperium.zIPS.appstore",
            "zipsVersion": "4.7.0",
            "appName": "zIPS",
            "tag1": "",
            "tag2": "",
            "incidentSummary": "Your device is not setup to use a PIN code, Password, or Pattern to lock your device. "
                               "By not using a PIN code, Password, or Pattern to lock your device, sensitive data on "
                               "the device could be exposed to attackers if your device is stolen or compromised. "
                               "It is advised that a PIN code, Password, or Pattern be enabled as a standard security practice "
                               "in securing your device and securing the sensitive data on the device.",
            "eventDetail": None
        }
    ]
}
RESPONSE_SEARCH_USERS = {
    "content": [
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
            "activationTokenUrl":
                "https://demo-device-api.zimperium.com/activation?stoken\...redirect_uri\u003dzips",
            "superuser": False,
            "staff": False,
            "phoneNumberVerified": False,
            "syncedFromMdm": False
        }
    ],
    "last": True,
    "totalPages": 1,
    "totalElements": 1,
    "first": True,
    "size": 20,
    "number": 0,
    "numberOfElements": 1
}
RESPONSE_USER_GET_BY_ID = {
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
RESPONSE_SEARCH_DEVICES = {
    "content": [
        {
            "zdid": "87a587de-283f-48c9-9ff2-047c8b025b6d",
            "deviceId": "1dbf5a9e-b0e8-4625-9205-6d9df8750c3f",
            "deviceHash": "3dce52cf609b70d00865fa8a4bbc3ccb49cdd05ea88dd897fe98c6e510f0a3",
            "mdmId": "1dbf5a9e-b0e8-4625-9205-6d9df8750c3f",
            "statusCode": 1,
            "status": "Active",
            "zipsVersion": "4.8.0",
            "lastSeen": "2019-02-01 05:13:12 UTC",
            "createdAt": "2019-02-01 05:13:12 UTC",
            "updatedDate": "2019-02-01 05:13:12 UTC",
            "country": "US",
            "countryCode": "310",
            "operatorAlpha": "AT\u0026T",
            "type": "iPhone",
            "zipsDistributionVersion": "n/a",

            "appName": "zIPS",
            "bundleId": "com.zimperium.vzips",
            "externalTrackingId1": "",
            "externalTrackingId2": "",
            "version": "4.8.0",
            "osUpgradeable": False,
            "osVulnerable": False,
            "model": "iPhoneXS Max",
            "osVersion": "12.0.0",
            "osType": "iOS",
            "userId": "868CEA8B-7796-44B6-B249-724A325EDE78",
            "email": "zauto@example.com",
            "firstName": "zAuto",
            "middleName": "Tool",
            "lastName": "QA",
            "systemToken": "automation-rest",
            "riskPostureCode": 0,
            "riskPosture": "Normal",
            "vulnerabilities": []
        }
    ],
    "last": True,
    "totalPages": 1,
    "totalElements": 1,
    "first": True,
    "numberOfElements": 1,
    "size": 20,
    "number": 0
}
RESPONSE_DEVICE_GET_BY_ID = {
    "zdid": "87a587de-283f-48c9-9ff2-047c8b025b6d",
    "deviceId": "1dbf5a9e-b0e8-4625-9205-6d9df8750c3f",
    "deviceHash": "3dce52cf609b70d00865fa8a4bbc3ccb8c49cdd05ea88dd897fe98c6e510f0a3",
    "statusCode": 1,
    "status": "Active",
    "zipsVersion": "4.8.0",
    "lastSeen": "2019-02-01 05:13:12 UTC",
    "createdAt": "2019-02-01 05:13:12 UTC",
    "updatedDate": "2019-02-01 05:13:12 UTC",
    "country": "US",
    "countryCode": "310",
    "operatorAlpha": "AT\u0026T",
    "type": "iPhone",
    "zipsDistributionVersion": "n/a",
    "appName": "zIPS",
    "bundleId": "com.zimperium.vzips",
    "externalTrackingId1": "",
    "externalTrackingId2": "",
    "version": "4.8.0",
    "osUpgradeable": False,
    "osVulnerable": False,
    "model": "iPhoneXS Max",
    "osVersion": "12.0.0",
    "osType": "iOS",
    "userId": "868CEA8B-7796-44B6-B249-724A325EDE78",
    "email": "zauto@example.com",
    "firstName": "zAuto",
    "middleName": "Tool",
    "lastName": "QA",
    "systemToken": "automation-rest",
    "riskPostureCode": 0,
    "riskPosture": "Normal",
    "vulnerabilities": []
}
RESPONSE_APP_CLASSIFICATION_GET = [
    {
        "objectId": "d28bf74c-c978-488e-a7e4-e15f4d864927",
        "systemToken": "joseph",
        "hash": "aad9b2fd4606467f06931d72048ee1dff137cbc9b601860a88ad6a2c092",
        "modifiedDate": "2018-12-14 12:37:52 UTC",
        "classification": "Legitimate",
        "name": "Test",
        "version": "2.1.3",
        "score": 0.00,
        "privacyEnum": 0,
        "securityEnum": 1,
        "processState": "AVAILABLE",
        "deviceCount": 0,
        "metadata": {
            "name": "Test",
            "bundleId": "com.apple.Test",
            "applicationSize": 10600448,
            "id": "045c470c-e6f4-3b86-9da6-5b1005c8459f",
            "version": "2.1.3",
            "hash": "aad9b2fd4606467f06931d72048ee1dff137cbc9b601860a88ad6a2c092",
            "platform": "iOS"
        },
        "securityRisk": "Medium",
        "privacyRisk": "Low"
    }
]
