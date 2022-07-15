RESPONSE_LIST_GROUPS = {
    "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#groups",
    "value": [
        {
            "classification": None,
            "createdDateTime": "2018-12-26T09:51:32Z",
            "creationOptions": [],
            "deletedDateTime": None,
            "description": None,
            "displayName": "TestDist",
            "groupTypes": [],
            "id": "TestDist",
            "isAssignableToRole": None,
            "mail": "testdist@demistodev.onmicrosoft.com",
            "mailEnabled": True,
            "mailNickname": "testdist",
            "onPremisesDomainName": None,
            "onPremisesLastSyncDateTime": None,
            "onPremisesNetBiosName": None,
            "onPremisesProvisioningErrors": [],
            "onPremisesSamAccountName": None,
            "onPremisesSecurityIdentifier": None,
            "onPremisesSyncEnabled": None,
            "preferredDataLocation": None,
            "proxyAddresses": [
                "SMTP:testdist@demistodev.onmicrosoft.com"
            ],
            "renewedDateTime": "2018-12-26T09:51:32Z",
            "resourceBehaviorOptions": [],
            "resourceProvisioningOptions": [],
            "securityEnabled": False,
            "securityIdentifier": None,
            "visibility": None
        },
        {
            "classification": None,
            "createdDateTime": "2019-08-24T09:39:03Z",
            "creationOptions": [
                "Team",
                "ExchangeProvisioningFlags:3552"
            ],
            "deletedDateTime": None,
            "description": "DemistoTeam",
            "displayName": "DemistoTeam",
            "groupTypes": [
                "Unified"
            ],
            "id": "DemistoTeam",
            "isAssignableToRole": None,
            "mail": "DemistoTeam@demistodev.onmicrosoft.com",
            "mailEnabled": True,
            "mailNickname": "DemistoTeam",
            "onPremisesDomainName": None,
            "onPremisesLastSyncDateTime": None,
            "onPremisesNetBiosName": None,
            "onPremisesProvisioningErrors": [],
            "onPremisesSamAccountName": None,
            "onPremisesSecurityIdentifier": None,
            "onPremisesSyncEnabled": None,
            "preferredDataLocation": None,
            "proxyAddresses": [
                "SPO:SPO_6450fabe-0048-4804-8503-9f0f0694662f@SPO_ebac1a16-81bf-449b-8d43-5732c3c1d999",
                "SMTP:DemistoTeam@demistodev.onmicrosoft.com"
            ],
            "renewedDateTime": "2019-08-24T09:39:03Z",
            "resourceBehaviorOptions": [
                "HideGroupInOutlook",
                "SubscribeMembersToCalendarEventsDisabled",
                "WelcomeEmailDisabled"
            ],
            "resourceProvisioningOptions": [
                "Team"
            ],
            "securityEnabled": False,
            "securityIdentifier": None,
            "visibility": "Public"
        }
    ]
}
RESPONSE_GET_GROUP = {
    "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#groups/$entity",
    "classification": None,
    "createdDateTime": "2019-08-24T09:39:03Z",
    "creationOptions": [
        "Team",
        "ExchangeProvisioningFlags:3552"
    ],
    "deletedDateTime": None,
    "description": "DemistoTeam",
    "displayName": "DemistoTeam",
    "groupTypes": [
        "Unified"
    ],
    "id": "DemistoTeam",
    "isAssignableToRole": None,
    "mail": "DemistoTeam@demistodev.onmicrosoft.com",
    "mailEnabled": True,
    "mailNickname": "DemistoTeam",
    "onPremisesDomainName": None,
    "onPremisesLastSyncDateTime": None,
    "onPremisesNetBiosName": None,
    "onPremisesProvisioningErrors": [],
    "onPremisesSamAccountName": None,
    "onPremisesSecurityIdentifier": None,
    "onPremisesSyncEnabled": None,
    "preferredDataLocation": None,
    "proxyAddresses": [
        "SPO:SPO_6450fabe-0048-4804-8503-9f0f0694662f@SPO_ebac1a16-81bf-449b-8d43-5732c3c1d999",
        "SMTP:DemistoTeam@demistodev.onmicrosoft.com"
    ],
    "renewedDateTime": "2019-08-24T09:39:03Z",
    "resourceBehaviorOptions": [
        "HideGroupInOutlook",
        "SubscribeMembersToCalendarEventsDisabled",
        "WelcomeEmailDisabled"
    ],
    "resourceProvisioningOptions": [
        "Team"
    ],
    "securityEnabled": False,
    "securityIdentifier": None,
    "visibility": "Public"
}
RESPONSE_CREATE_GROUP = {
    "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#groups/$entity",
    "classification": None,
    "createdDateTime": "2019-11-05T10:15:55Z",
    "creationOptions": [],
    "deletedDateTime": None,
    "description": None,
    "displayName": "my_unit_test_group",
    "groupTypes": [],
    "id": "1baabf76-0f12-4336-922d-c9669a0d4027",
    "isAssignableToRole": None,
    "mail": None,
    "mailEnabled": False,
    "mailNickname": "unit_test",
    "onPremisesDomainName": None,
    "onPremisesLastSyncDateTime": None,
    "onPremisesNetBiosName": None,
    "onPremisesProvisioningErrors": [],
    "onPremisesSamAccountName": None,
    "onPremisesSecurityIdentifier": None,
    "onPremisesSyncEnabled": None,
    "preferredDataLocation": None,
    "proxyAddresses": [],
    "renewedDateTime": "2019-11-05T10:15:55Z",
    "resourceBehaviorOptions": [],
    "resourceProvisioningOptions": [],
    "securityEnabled": True,
    "securityIdentifier": "S-1-12-1-464174966-1127616274-1724460434-658509210",
    "visibility": None
}
RESPONSE_LIST_MEMBERS_UNDER_100 = {
        "@odata.context": "someLink",
        "value": [
            {
                "id": "ID1",
                "businessPhones": [
                ],
                "displayName": "mock1",
                "givenName": "mock1",
                "jobTitle": "test",
                "mail": "mock1@demistodev.onmicrosoft.com",
                "mobilePhone": "None",
                "officeLocation": "None",
                "preferredLanguage": "en-US",
                "surname": "mock1",
                "userPrincipalName": "mock1@demistodev.onmicrosoft.com"
            },
            {
                "@odata.type": "#microsoft.graph.user",
                "id": "ID2",
                "businessPhones": [

                ],
                "displayName": "mock2",
                "givenName": "mock2",
                "jobTitle": "None",
                "mail": "mock2@demistodev.onmicrosoft.com",
                "mobilePhone": "050505050",
                "officeLocation": "None",
                "preferredLanguage": "en-US",
                "surname": "mock2",
                "userPrincipalName": "mock2@demistodev.onmicrosoft.com"
            },
            {
                "@odata.type": "#microsoft.graph.user",
                "id": "ID3",
                "businessPhones": [

                ],
                "displayName": "mock3",
                "givenName": "mock3",
                "jobTitle": "None",
                "mail": "None",
                "mobilePhone": "None",
                "officeLocation": "None",
                "preferredLanguage": "None",
                "surname": "mock3",
                "userPrincipalName": "mock3@demistodev.onmicrosoft.com"
            }
        ]
    }
RESPONSE_LIST_MEMBERS_ABOVE_100 = {
        "@odata.context": "someLink",
        "@odata.nextLink": "someNextLink",
        "value": [
            {
                "@odata.type": "#microsoft.graph.user",
                "id": "ID1",
                "businessPhones": [
                ],
                "displayName": "mock1",
                "givenName": "mock1",
                "jobTitle": "test",
                "mail": "mock1@demistodev.onmicrosoft.com",
                "mobilePhone": "None",
                "officeLocation": "None",
                "preferredLanguage": "en-US",
                "surname": "mock1",
                "userPrincipalName": "mock1@demistodev.onmicrosoft.com"
            },
            {
                "@odata.type": "#microsoft.graph.user",
                "id": "ID2",
                "businessPhones": [

                ],
                "displayName": "mock2",
                "givenName": "mock2",
                "jobTitle": "None",
                "mail": "mock2@demistodev.onmicrosoft.com",
                "mobilePhone": "050505050",
                "officeLocation": "None",
                "preferredLanguage": "en-US",
                "surname": "mock2",
                "userPrincipalName": "mock2@demistodev.onmicrosoft.com"
            },
            {
                "@odata.type": "#microsoft.graph.user",
                "id": "ID3",
                "businessPhones": [

                ],
                "displayName": "mock3",
                "givenName": "mock3",
                "jobTitle": "None",
                "mail": "None",
                "mobilePhone": "None",
                "officeLocation": "None",
                "preferredLanguage": "None",
                "surname": "mock3",
                "userPrincipalName": "mock3@demistodev.onmicrosoft.com"
            }
        ]
}
