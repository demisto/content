EXPECTED_LIST_GROUPS = {
    "MSGraphGroups(val.ID === obj.ID)": [
        {
            "Classification": None,
            "CreatedDateTime": "2018-12-26T09:51:32Z",
            "DeletedDateTime": None,
            "Description": None,
            "DisplayName": "TestDist",
            "GroupTypes": [],
            "ID": "TestDist",
            "IsAssignableToRole": None,
            "Mail": "testdist@demistodev.onmicrosoft.com",
            "MailEnabled": True,
            "MailNickname": "testdist",
            "OnPremisesDomainName": None,
            "OnPremisesLastSyncDateTime": None,
            "OnPremisesSyncEnabled": None,
            "ProxyAddresses": [
                "SMTP:testdist@demistodev.onmicrosoft.com"
            ],
            "RenewedDateTime": "2018-12-26T09:51:32Z",
            "SecurityEnabled": False,
            "Visibility": None
        },
        {
            "Classification": None,
            "CreatedDateTime": "2019-08-24T09:39:03Z",
            "DeletedDateTime": None,
            "Description": "DemistoTeam",
            "DisplayName": "DemistoTeam",
            "GroupTypes": [
                "Unified"
            ],
            "ID": "DemistoTeam",
            "IsAssignableToRole": None,
            "Mail": "DemistoTeam@demistodev.onmicrosoft.com",
            "MailEnabled": True,
            "MailNickname": "DemistoTeam",
            "OnPremisesDomainName": None,
            "OnPremisesLastSyncDateTime": None,
            "OnPremisesSyncEnabled": None,
            "ProxyAddresses": [
                "SPO:SPO_6450fabe-0048-4804-8503-9f0f0694662f@SPO_ebac1a16-81bf-449b-8d43-5732c3c1d999",
                "SMTP:DemistoTeam@demistodev.onmicrosoft.com"
            ],
            "RenewedDateTime": "2019-08-24T09:39:03Z",
            "SecurityEnabled": False,
            "Visibility": "Public"
        }
    ]
}
EXPECTED_GET_GROUP = {
    "MSGraphGroups(val.ID === obj.ID)": {
        "Classification": None,
        "CreatedDateTime": "2019-08-24T09:39:03Z",
        "DeletedDateTime": None,
        "Description": "DemistoTeam",
        "DisplayName": "DemistoTeam",
        "GroupTypes": [
            "Unified"
        ],
        "ID": "DemistoTeam",
        "IsAssignableToRole": None,
        "Mail": "DemistoTeam@demistodev.onmicrosoft.com",
        "MailEnabled": True,
        "MailNickname": "DemistoTeam",
        "OnPremisesDomainName": None,
        "OnPremisesLastSyncDateTime": None,
        "OnPremisesSyncEnabled": None,
        "ProxyAddresses": [
            "SPO:SPO_6450fabe-0048-4804-8503-9f0f0694662f@SPO_ebac1a16-81bf-449b-8d43-5732c3c1d999",
            "SMTP:DemistoTeam@demistodev.onmicrosoft.com"
        ],
        "RenewedDateTime": "2019-08-24T09:39:03Z",
        "SecurityEnabled": False,
        "Visibility": "Public"
    }
}
EXPECTED_CREATE_GROUP = {
    "MSGraphGroups(val.ID === obj.ID)": {
        "Classification": None,
        "CreatedDateTime": "2019-11-05T10:15:55Z",
        "DeletedDateTime": None,
        "Description": None,
        "DisplayName": "my_unit_test_group",
        "GroupTypes": [],
        "ID": "1baabf76-0f12-4336-922d-c9669a0d4027",
        "IsAssignableToRole": None,
        "Mail": None,
        "MailEnabled": False,
        "MailNickname": "unit_test",
        "OnPremisesDomainName": None,
        "OnPremisesLastSyncDateTime": None,
        "OnPremisesSyncEnabled": None,
        "ProxyAddresses": [],
        "RenewedDateTime": "2019-11-05T10:15:55Z",
        "SecurityEnabled": True,
        "Visibility": None
    }
}
EXPECTED_GET_DELTA = {
    "MSGraphGroupsDelta(val.ID === obj.ID)": [
        {
            "CreatedDateTime": "2017-10-29T10:56:35Z",
            "DisplayName": "AAD DC Administrators",
            "ID": "id_",
            "MailEnabled": False,
            "MailNickname": "AADDCAdministrators",
            "RenewedDateTime": "2017-10-29T10:56:35Z",
            "SecurityEnabled": True,
            "Visibility": None
        }
    ]
}
