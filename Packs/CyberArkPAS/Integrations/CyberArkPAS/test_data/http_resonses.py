ADD_USER_RAW_RESPONSE = {
    "authenticationMethod": ["AuthTypePass"],
    "businessAddress": {"workCity": "", "workCountry": "", "workState": "", "workStreet": "", "workZip": ""},
    "changePassOnNextLogon": True,
    "componentUser": False,
    "description": "new user for test",
    "distinguishedName": "",
    "enableUser": True,
    "expiryDate": -62135578800,
    "groupsMembership": [],
    "id": 123,
    "internet": {"businessEmail": "usertest@test.com", "homeEmail": "", "homePage": "", "otherEmail": ""},
    "lastSuccessfulLoginDate": 1594756313,
    "location": "\\",
    "passwordNeverExpires": False,
    "personalDetails": {
        "city": "",
        "country": "",
        "department": "",
        "firstName": "user",
        "lastName": "test",
        "middleName": "",
        "organization": "",
        "profession": "testing integrations",
        "state": "",
        "street": "",
        "title": "",
        "zip": "",
    },
    "phones": {"businessNumber": "", "cellularNumber": "", "faxNumber": "", "homeNumber": "", "pagerNumber": ""},
    "source": "CyberArkPAS",
    "suspended": False,
    "unAuthorizedInterfaces": [],
    "userType": "EPVUser",
    "username": "TestUser",
    "vaultAuthorization": [],
}

UPDATE_USER_RAW_RESPONSE = {
    "authenticationMethod": ["AuthTypePass"],
    "businessAddress": {"workCity": "", "workCountry": "", "workState": "", "workStreet": "", "workZip": ""},
    "changePassOnNextLogon": True,
    "componentUser": False,
    "description": "updated description",
    "distinguishedName": "",
    "enableUser": True,
    "expiryDate": -62135578800,
    "groupsMembership": [],
    "id": 123,
    "internet": {"businessEmail": "update@test.com", "homeEmail": "", "homePage": "", "otherEmail": ""},
    "lastSuccessfulLoginDate": 1594756313,
    "location": "\\",
    "passwordNeverExpires": False,
    "personalDetails": {
        "city": "",
        "country": "",
        "department": "",
        "firstName": "test1",
        "lastName": "updated-name",
        "middleName": "",
        "organization": "",
        "profession": "test1",
        "state": "",
        "street": "",
        "title": "",
        "zip": "",
    },
    "phones": {"businessNumber": "", "cellularNumber": "", "faxNumber": "", "homeNumber": "", "pagerNumber": ""},
    "source": "CyberArkPAS",
    "suspended": False,
    "unAuthorizedInterfaces": [],
    "userType": "EPVUser",
    "username": "TestUser1",
    "vaultAuthorization": [],
}

GET_USERS_RAW_RESPONSE = {
    "Total": 2,
    "Users": [
        {
            "componentUser": False,
            "id": 2,
            "location": "\\",
            "personalDetails": {"firstName": "", "lastName": "", "middleName": ""},
            "source": "CyberArkPAS",
            "userType": "Built-InAdmins",
            "username": "Administrator",
            "vaultAuthorization": [
                "AddUpdateUsers",
                "AddSafes",
                "AddNetworkAreas",
                "ManageDirectoryMapping",
                "ManageServerFileCategories",
                "AuditUsers",
                "BackupAllSafes",
                "RestoreAllSafes",
                "ResetUsersPasswords",
                "ActivateUsers",
            ],
        },
        {
            "componentUser": False,
            "id": 3,
            "location": "\\",
            "personalDetails": {"firstName": "", "lastName": "", "middleName": ""},
            "source": "CyberArkPAS",
            "userType": "Built-InAdmins",
            "username": "Auditor",
            "vaultAuthorization": ["AuditUsers"],
        },
    ],
}

ADD_SAFE_RAW_RESPONSE = {
    "AutoPurgeEnabled": False,
    "Description": "safe for tests",
    "Location": "\\",
    "ManagingCPM": "",
    "NumberOfDaysRetention": 100,
    "NumberOfVersionsRetention": None,
    "OLACEnabled": True,
    "SafeName": "TestSafe",
}

UPDATE_SAFE_RAW_RESPONSE = {
    "AutoPurgeEnabled": False,
    "Description": "UpdatedSafe",
    "Location": "\\",
    "ManagingCPM": "",
    "NumberOfDaysRetention": 150,
    "NumberOfVersionsRetention": None,
    "OLACEnabled": True,
    "SafeName": "UpdatedName",
}

GET_SAFE_BY_NAME_RAW_RESPONSE = {
    "AutoPurgeEnabled": False,
    "Description": "safe for tests",
    "Location": "\\",
    "ManagingCPM": "",
    "NumberOfDaysRetention": 100,
    "NumberOfVersionsRetention": None,
    "OLACEnabled": True,
    "SafeName": "TestSafe",
}

GET_LIST_SAFES_RAW_RESPONSE = {
    "Safes": [
        {"Description": "", "Location": "\\", "SafeName": "VaultInternal", "SafeUrlId": "VaultInternal"},
        {"Description": "", "Location": "\\", "SafeName": "Notification Engine", "SafeUrlId": "Notification%20Engine"},
    ]
}


ADD_SAFE_MEMBER_RAW_RESPONSE = {
    "member": {
        "MemberName": "TestUser",
        "MembershipExpirationDate": "",
        "Permissions": [
            {"Key": "UseAccounts", "Value": False},
            {"Key": "RetrieveAccounts", "Value": False},
            {"Key": "ListAccounts", "Value": False},
            {"Key": "AddAccounts", "Value": False},
            {"Key": "UpdateAccountContent", "Value": False},
            {"Key": "UpdateAccountProperties", "Value": False},
            {"Key": "InitiateCPMAccountManagementOperations", "Value": False},
            {"Key": "SpecifyNextAccountContent", "Value": False},
            {"Key": "RenameAccounts", "Value": False},
            {"Key": "DeleteAccounts", "Value": False},
            {"Key": "UnlockAccounts", "Value": False},
            {"Key": "ManageSafe", "Value": False},
            {"Key": "ManageSafeMembers", "Value": False},
            {"Key": "BackupSafe", "Value": False},
            {"Key": "ViewAuditLog", "Value": False},
            {"Key": "ViewSafeMembers", "Value": False},
            {"Key": "AccessWithoutConfirmation", "Value": False},
            {"Key": "CreateFolders", "Value": False},
            {"Key": "DeleteFolders", "Value": False},
            {"Key": "MoveAccountsAndFolders", "Value": False},
            {"Key": "RequestsAuthorizationLevel", "Value": 0},
        ],
        "SearchIn": "vault",
    }
}

UPDATE_SAFE_MEMBER_RAW_RESPONSE = {
    "member": {
        "MemberName": "TestUser",
        "MembershipExpirationDate": "",
        "Permissions": [
            {"Key": "UseAccounts", "Value": True},
            {"Key": "RetrieveAccounts", "Value": False},
            {"Key": "ListAccounts", "Value": False},
            {"Key": "AddAccounts", "Value": False},
            {"Key": "UpdateAccountContent", "Value": False},
            {"Key": "UpdateAccountProperties", "Value": False},
            {"Key": "InitiateCPMAccountManagementOperations", "Value": False},
            {"Key": "SpecifyNextAccountContent", "Value": False},
            {"Key": "RenameAccounts", "Value": False},
            {"Key": "DeleteAccounts", "Value": False},
            {"Key": "UnlockAccounts", "Value": False},
            {"Key": "ManageSafe", "Value": False},
            {"Key": "ManageSafeMembers", "Value": False},
            {"Key": "BackupSafe", "Value": False},
            {"Key": "ViewAuditLog", "Value": False},
            {"Key": "ViewSafeMembers", "Value": False},
            {"Key": "AccessWithoutConfirmation", "Value": False},
            {"Key": "CreateFolders", "Value": False},
            {"Key": "DeleteFolders", "Value": False},
            {"Key": "MoveAccountsAndFolders", "Value": False},
            {"Key": "RequestsAuthorizationLevel", "Value": 0},
        ],
        "SearchIn": "vault",
    }
}

LIST_SAFE_MEMBER_RAW_RESPONSE = {
    "SafeMembers": [
        {
            "IsExpiredMembershipEnable": False,
            "IsPredefinedUser": True,
            "MemberName": "Administrator",
            "MemberType": "User",
            "MembershipExpirationDate": None,
            "Permissions": {
                "AccessWithoutConfirmation": True,
                "AddAccounts": True,
                "BackupSafe": True,
                "CreateFolders": True,
                "DeleteAccounts": True,
                "DeleteFolders": True,
                "InitiateCPMAccountManagementOperations": True,
                "ListAccounts": True,
                "ManageSafe": True,
                "ManageSafeMembers": True,
                "MoveAccountsAndFolders": True,
                "RenameAccounts": True,
                "RequestsAuthorizationLevel1": True,
                "RequestsAuthorizationLevel2": False,
                "RetrieveAccounts": True,
                "SpecifyNextAccountContent": True,
                "UnlockAccounts": True,
                "UpdateAccountContent": True,
                "UpdateAccountProperties": True,
                "UseAccounts": True,
                "ViewAuditLog": True,
                "ViewSafeMembers": True,
            },
        },
        {
            "IsExpiredMembershipEnable": False,
            "IsPredefinedUser": True,
            "MemberName": "Master",
            "MemberType": "User",
            "MembershipExpirationDate": None,
            "Permissions": {
                "AccessWithoutConfirmation": True,
                "AddAccounts": True,
                "BackupSafe": True,
                "CreateFolders": True,
                "DeleteAccounts": True,
                "DeleteFolders": True,
                "InitiateCPMAccountManagementOperations": True,
                "ListAccounts": True,
                "ManageSafe": True,
                "ManageSafeMembers": True,
                "MoveAccountsAndFolders": True,
                "RenameAccounts": True,
                "RequestsAuthorizationLevel1": False,
                "RequestsAuthorizationLevel2": False,
                "RetrieveAccounts": True,
                "SpecifyNextAccountContent": True,
                "UnlockAccounts": True,
                "UpdateAccountContent": True,
                "UpdateAccountProperties": True,
                "UseAccounts": True,
                "ViewAuditLog": True,
                "ViewSafeMembers": True,
            },
        },
    ]
}

ADD_ACCOUNT_RAW_RESPONSE = {
    "address": "/",
    "categoryModificationTime": 1594835018,
    "createdTime": 1594838456,
    "id": "77_4",
    "name": "TestAccount1",
    "platformId": "WinServerLocal",
    "safeName": "TestSafe",
    "secretManagement": {"automaticManagementEnabled": True, "lastModifiedTime": 1594824056},
    "secretType": "password",
    "userName": "TestUser",
}

GET_ACCOUNT_RAW_RESPONSE = {
    "categoryModificationTime": 1597581174,
    "id": "11_1",
    "name": "Operating System-UnixSSH",
    "address": "address",
    "userName": "firecall2",
    "platformId": "UnixSSH",
    "safeName": "Linux Accounts",
    "secretType": "password",
    "platformAccountProperties": {"UseSudoOnReconcile": "No", "Tags": "SSH"},
    "secretManagement": {
        "automaticManagementEnabled": True,
        "status": "success",
        "lastModifiedTime": 1595417469,
        "lastReconciledTime": 1576120341,
    },
    "createdTime": 1595431869,
}

UPDATE_ACCOUNT_RAW_RESPONSE = {
    "address": "/",
    "categoryModificationTime": 1594835018,
    "createdTime": 1594838456,
    "id": "77_4",
    "name": "NewName",
    "platformId": "WinServerLocal",
    "safeName": "TestSafe",
    "secretManagement": {"automaticManagementEnabled": True, "lastModifiedTime": 1594824056},
    "secretType": "password",
    "userName": "TestUser",
}

GET_LIST_ACCOUNT_RAW_RESPONSE = {
    "count": 2,
    "nextLink": "api/Accounts?offset=2\u0026limit=2",
    "value": [
        {
            "address": "string",
            "categoryModificationTime": 1594569595,
            "createdTime": 1594573679,
            "id": "2_6",
            "name": "account1",
            "platformAccountProperties": {},
            "platformId": "Oracle",
            "safeName": "VaultInternal",
            "secretManagement": {"automaticManagementEnabled": True, "lastModifiedTime": 1594559279},
            "secretType": "password",
            "userName": "string",
        },
        {
            "address": "10.0.0.5",
            "categoryModificationTime": 1583345933,
            "createdTime": 1573127750,
            "id": "2_3",
            "name": "cybr.com.pass",
            "platformAccountProperties": {},
            "platformId": "WinDomain",
            "safeName": "VaultInternal",
            "secretManagement": {
                "automaticManagementEnabled": False,
                "lastModifiedTime": 1573109750,
                "manualManagementReason": "NoReason",
            },
            "secretType": "password",
            "userName": "vaultbind@cybr.com",
        },
    ],
}

GET_LIST_ACCOUNT_ACTIVITIES_RAW_RESPONSE = {
    "Activities": [
        {
            "Action": "Rename File",
            "ActionID": 124,
            "Alert": False,
            "ClientID": "PVWA",
            "Date": 1594838533,
            "MoreInfo": "NewName",
            "Reason": "",
            "User": "Administrator",
        },
        {
            "Action": "Store password",
            "ActionID": 294,
            "Alert": False,
            "ClientID": "PVWA",
            "Date": 1594838456,
            "MoreInfo": "",
            "Reason": "",
            "User": "Administrator",
        },
    ]
}

GET_SECURITY_EVENTS_RAW_RESPONSE = [
    {
        "id": "5f0ea000e4b0ba4baf5d1910",
        "type": "VaultViaIrregularIp",
        "score": 27.656250000000004,
        "createTime": 1594793984000,
        "lastUpdateTime": 1594793984000,
        "audits": [
            {
                "id": "5f0ea000e4b0ba4baf5d190e",
                "type": "VAULT_LOGON",
                "sensorType": "VAULT",
                "action": "Logon",
                "createTime": 1594793984000,
                "vaultUser": "Administrator",
                "source": {"mOriginalAddress": "17.111.13.67"},
                "cloudData": {},
            }
        ],
        "additionalData": {"station": "17.111.13.67", "reason": "ip", "vault_user": "administrator"},
        "mStatus": "OPEN",
    },
    {
        "id": "5f0c5b5de4b0ba4baf5c66db",
        "type": "VaultViaIrregularIp",
        "score": 29.414062500000004,
        "createTime": 1594645338000,
        "lastUpdateTime": 1594645338000,
        "audits": [
            {
                "id": "5f0c5b5de4b0ba4baf5c653e",
                "type": "VAULT_LOGON",
                "sensorType": "VAULT",
                "action": "Logon",
                "createTime": 1594645338000,
                "vaultUser": "Administrator",
                "source": {
                    "mOriginalAddress": "17.111.13.67",
                    "mResolvedAddress": {
                        "mOriginalAddress": "17.111.13.67",
                        "mAddress": "17.111.13.67",
                        "mHostName": "17.111.13.67",
                        "mFqdn": "17.111.13.67.bb.netvision.net.il",
                    },
                },
                "cloudData": {},
            }
        ],
        "additionalData": {"station": "17.111.13.67", "reason": "ip", "vault_user": "administrator"},
        "mStatus": "OPEN",
    },
    {
        "id": "5f0b4e53e4b0ba4baf5c43ed",
        "type": "VaultViaIrregularIp",
        "score": 29.414062500000004,
        "createTime": 1594576467000,
        "lastUpdateTime": 1594576467000,
        "audits": [
            {
                "id": "5f0b4e53e4b0ba4baf5c43eb",
                "type": "VAULT_LOGON",
                "sensorType": "VAULT",
                "action": "Logon",
                "createTime": 1594576467000,
                "vaultUser": "Administrator",
                "source": {
                    "mOriginalAddress": "17.111.13.67",
                    "mResolvedAddress": {
                        "mOriginalAddress": "17.111.13.67",
                        "mAddress": "17.111.13.67",
                        "mHostName": "17.111.13.67",
                        "mFqdn": "17.111.13.67.bb.netvision.net.il",
                    },
                },
                "cloudData": {},
            }
        ],
        "additionalData": {"station": "17.111.13.67", "reason": "ip", "vault_user": "administrator"},
        "mStatus": "OPEN",
    },
    {
        "id": "5f0b4320e4b0ba4baf5c2b05",
        "type": "VaultViaIrregularIp",
        "score": 29.414062500000004,
        "createTime": 1594573600000,
        "lastUpdateTime": 1594573600000,
        "audits": [
            {
                "id": "5f0b4320e4b0ba4baf5c2b03",
                "type": "VAULT_LOGON",
                "sensorType": "VAULT",
                "action": "Logon",
                "createTime": 1594573600000,
                "vaultUser": "Administrator",
                "source": {
                    "mOriginalAddress": "17.111.13.67",
                    "mResolvedAddress": {
                        "mOriginalAddress": "17.111.13.67",
                        "mAddress": "17.111.13.67",
                        "mHostName": "17.111.13.67",
                        "mFqdn": "17.111.13.67.bb.netvision.net.il",
                    },
                },
                "cloudData": {},
            }
        ],
        "additionalData": {"station": "17.111.13.67", "reason": "ip", "vault_user": "administrator"},
        "mStatus": "OPEN",
    },
    {
        "id": "5f0b3064e4b0ba4baf5c1113",
        "type": "VaultViaIrregularIp",
        "score": 29.414062500000004,
        "createTime": 1594568804000,
        "lastUpdateTime": 1594568804000,
        "audits": [
            {
                "id": "5f0b3064e4b0ba4baf5c1111",
                "type": "VAULT_LOGON",
                "sensorType": "VAULT",
                "action": "Logon",
                "createTime": 1594568804000,
                "vaultUser": "Administrator",
                "source": {
                    "mOriginalAddress": "17.111.13.67",
                    "mResolvedAddress": {
                        "mOriginalAddress": "17.111.13.67",
                        "mAddress": "17.111.13.67",
                        "mHostName": "17.111.13.67",
                        "mFqdn": "17.111.13.67.bb.netvision.net.il",
                    },
                },
                "cloudData": {},
            }
        ],
        "additionalData": {"station": "17.111.13.67", "reason": "ip", "vault_user": "administrator"},
        "mStatus": "OPEN",
    },
]

GET_SECURITY_EVENTS_WITH_UNNECESSARY_INCIDENT_RAW_RESPONSE = [
    {
        "id": "5f0ea000e4b0ba4baf5d1910",
        "type": "VaultViaIrregularIp",
        "score": 27.656250000000004,
        "createTime": 1594793984000,
        "lastUpdateTime": 1594793984000,
        "audits": [
            {
                "id": "5f0ea000e4b0ba4baf5d190e",
                "type": "VAULT_LOGON",
                "sensorType": "VAULT",
                "action": "Logon",
                "createTime": 1594793984000,
                "vaultUser": "Administrator",
                "source": {"mOriginalAddress": "17.111.13.67"},
                "cloudData": {},
            }
        ],
        "additionalData": {"station": "17.111.13.67", "reason": "ip", "vault_user": "administrator"},
        "mStatus": "OPEN",
    },
    {
        "id": "5f0c5b5de4b0ba4baf5c66db",
        "type": "VaultViaIrregularIp",
        "score": 29.414062500000004,
        "createTime": 1594645338000,
        "lastUpdateTime": 1594645338000,
        "audits": [
            {
                "id": "5f0c5b5de4b0ba4baf5c653e",
                "type": "VAULT_LOGON",
                "sensorType": "VAULT",
                "action": "Logon",
                "createTime": 1594645338000,
                "vaultUser": "Administrator",
                "source": {
                    "mOriginalAddress": "17.111.13.67",
                    "mResolvedAddress": {
                        "mOriginalAddress": "17.111.13.67",
                        "mAddress": "17.111.13.67",
                        "mHostName": "17.111.13.67",
                        "mFqdn": "17.111.13.67.bb.netvision.net.il",
                    },
                },
                "cloudData": {},
            }
        ],
        "additionalData": {"station": "17.111.13.67", "reason": "ip", "vault_user": "administrator"},
        "mStatus": "OPEN",
    },
    {
        "id": "5f0b4e53e4b0ba4baf5c43ed",
        "type": "VaultViaIrregularIp",
        "score": 29.414062500000004,
        "createTime": 1594576467000,
        "lastUpdateTime": 1594576467000,
        "audits": [
            {
                "id": "5f0b4e53e4b0ba4baf5c43eb",
                "type": "VAULT_LOGON",
                "sensorType": "VAULT",
                "action": "Logon",
                "createTime": 1594576467000,
                "vaultUser": "Administrator",
                "source": {
                    "mOriginalAddress": "17.111.13.67",
                    "mResolvedAddress": {
                        "mOriginalAddress": "17.111.13.67",
                        "mAddress": "17.111.13.67",
                        "mHostName": "17.111.13.67",
                        "mFqdn": "17.111.13.67.bb.netvision.net.il",
                    },
                },
                "cloudData": {},
            }
        ],
        "additionalData": {"station": "17.111.13.67", "reason": "ip", "vault_user": "administrator"},
        "mStatus": "OPEN",
    },
    {
        "id": "5f0b4320e4b0ba4baf5c2b05",
        "type": "VaultViaIrregularIp",
        "score": 29.414062500000004,
        "createTime": 1594573600000,
        "lastUpdateTime": 1594573600000,
        "audits": [
            {
                "id": "5f0b4320e4b0ba4baf5c2b03",
                "type": "VAULT_LOGON",
                "sensorType": "VAULT",
                "action": "Logon",
                "createTime": 1594573600000,
                "vaultUser": "Administrator",
                "source": {
                    "mOriginalAddress": "17.111.13.67",
                    "mResolvedAddress": {
                        "mOriginalAddress": "17.111.13.67",
                        "mAddress": "17.111.13.67",
                        "mHostName": "17.111.13.67",
                        "mFqdn": "17.111.13.67.bb.netvision.net.il",
                    },
                },
                "cloudData": {},
            }
        ],
        "additionalData": {"station": "17.111.13.67", "reason": "ip", "vault_user": "administrator"},
        "mStatus": "OPEN",
    },
]

GET_SECURITY_EVENTS_WITH_15_INCIDENT_RAW_RESPONSE = [
    {
        "id": "5ebd5480e4b07501bd67d51c",
        "type": "InteractiveLogonWithServiceAccount",
        "score": 60.0,
        "createTime": 1589466020171,
        "lastUpdateTime": 1595333762775,
        "audits": [
            {
                "id": "5ebd5479e4b07501bd67d176",
                "type": "WINDOWS_LOGON",
                "sensorType": "SIEM",
                "action": "Logon",
                "createTime": 1589466020171,
                "account": {
                    "accountAsStr": "administrator@cybr.com",
                    "type": "DOMAIN",
                    "account": {"mDomain": "cybr.com", "spnList": [], "mUser": "administrator"},
                },
                "source": {
                    "mOriginalAddress": "10.0.0.5",
                    "mResolvedAddress": {
                        "mOriginalAddress": "dc01.cybr.com",
                        "mAddress": "10.0.0.5",
                        "mHostName": "dc01",
                        "mFqdn": "dc01.cybr.com",
                    },
                },
                "target": {
                    "mOriginalAddress": "dc01.cybr.com",
                    "mResolvedAddress": {
                        "mOriginalAddress": "dc01.cybr.com",
                        "mAddress": "10.0.0.5",
                        "mHostName": "dc01",
                        "mFqdn": "dc01.cybr.com",
                    },
                },
                "cloudData": {},
                "accountId": "27_3",
            }
        ],
        "additionalData": {"aggregation_count": 12},
        "mStatus": "OPEN",
    },
    {
        "id": "5f14495ce4b0ba4baf5efd83",
        "type": "VaultViaIrregularIp",
        "score": 27.656250000000004,
        "createTime": 1595165020000,
        "lastUpdateTime": 1595165020000,
        "audits": [
            {
                "id": "5f14495ce4b0ba4baf5efd81",
                "type": "VAULT_LOGON",
                "sensorType": "VAULT",
                "action": "Logon",
                "createTime": 1595165020000,
                "vaultUser": "Administrator",
                "source": {"mOriginalAddress": "17.111.13.67"},
                "cloudData": {},
            }
        ],
        "additionalData": {"station": "17.111.13.67", "reason": "ip", "vault_user": "administrator"},
        "mStatus": "OPEN",
    },
    {
        "id": "5f144943e4b0ba4baf5efce5",
        "type": "VaultViaIrregularIp",
        "score": 27.656250000000004,
        "createTime": 1595164995000,
        "lastUpdateTime": 1595164995000,
        "audits": [
            {
                "id": "5f144943e4b0ba4baf5efce3",
                "type": "VAULT_LOGON",
                "sensorType": "VAULT",
                "action": "Logon",
                "createTime": 1595164995000,
                "vaultUser": "Administrator",
                "source": {"mOriginalAddress": "17.111.13.67"},
                "cloudData": {},
            }
        ],
        "additionalData": {"station": "17.111.13.67", "reason": "ip", "vault_user": "administrator"},
        "mStatus": "OPEN",
    },
    {
        "id": "5f14492fe4b0ba4baf5efbf7",
        "type": "VaultViaIrregularIp",
        "score": 27.656250000000004,
        "createTime": 1595164975000,
        "lastUpdateTime": 1595164975000,
        "audits": [
            {
                "id": "5f14492fe4b0ba4baf5efbf4",
                "type": "VAULT_LOGON",
                "sensorType": "VAULT",
                "action": "Logon",
                "createTime": 1595164975000,
                "vaultUser": "Administrator",
                "source": {"mOriginalAddress": "17.111.13.67"},
                "cloudData": {},
            }
        ],
        "additionalData": {"station": "17.111.13.67", "reason": "ip", "vault_user": "administrator"},
        "mStatus": "OPEN",
    },
    {
        "id": "5f13f9c9e4b0ba4baf5ef447",
        "type": "VaultViaIrregularIp",
        "score": 27.656250000000004,
        "createTime": 1595144649000,
        "lastUpdateTime": 1595144649000,
        "audits": [
            {
                "id": "5f13f9c9e4b0ba4baf5ef445",
                "type": "VAULT_LOGON",
                "sensorType": "VAULT",
                "action": "Logon",
                "createTime": 1595144649000,
                "vaultUser": "Administrator",
                "source": {"mOriginalAddress": "17.111.13.67"},
                "cloudData": {},
            }
        ],
        "additionalData": {"station": "17.111.13.67", "reason": "ip", "vault_user": "administrator"},
        "mStatus": "OPEN",
    },
    {
        "id": "5f13f98ce4b0ba4baf5ef30b",
        "type": "VaultViaIrregularIp",
        "score": 27.656250000000004,
        "createTime": 1595144588000,
        "lastUpdateTime": 1595144588000,
        "audits": [
            {
                "id": "5f13f98ce4b0ba4baf5ef309",
                "type": "VAULT_LOGON",
                "sensorType": "VAULT",
                "action": "Logon",
                "createTime": 1595144588000,
                "vaultUser": "Administrator",
                "source": {"mOriginalAddress": "17.111.13.67"},
                "cloudData": {},
            }
        ],
        "additionalData": {"station": "17.111.13.67", "reason": "ip", "vault_user": "administrator"},
        "mStatus": "OPEN",
    },
    {
        "id": "5f13f951e4b0ba4baf5ef1d8",
        "type": "VaultViaIrregularIp",
        "score": 27.656250000000004,
        "createTime": 1595144529000,
        "lastUpdateTime": 1595144529000,
        "audits": [
            {
                "id": "5f13f951e4b0ba4baf5ef1d6",
                "type": "VAULT_LOGON",
                "sensorType": "VAULT",
                "action": "Logon",
                "createTime": 1595144529000,
                "vaultUser": "Administrator",
                "source": {"mOriginalAddress": "17.111.13.67"},
                "cloudData": {},
            }
        ],
        "additionalData": {"station": "17.111.13.67", "reason": "ip", "vault_user": "administrator"},
        "mStatus": "OPEN",
    },
    {
        "id": "5f13f914e4b0ba4baf5ef0ad",
        "type": "VaultViaIrregularIp",
        "score": 27.656250000000004,
        "createTime": 1595144468000,
        "lastUpdateTime": 1595144468000,
        "audits": [
            {
                "id": "5f13f914e4b0ba4baf5ef0ab",
                "type": "VAULT_LOGON",
                "sensorType": "VAULT",
                "action": "Logon",
                "createTime": 1595144468000,
                "vaultUser": "Administrator",
                "source": {"mOriginalAddress": "17.111.13.67"},
                "cloudData": {},
            }
        ],
        "additionalData": {"station": "17.111.13.67", "reason": "ip", "vault_user": "administrator"},
        "mStatus": "OPEN",
    },
    {
        "id": "5f13f8d8e4b0ba4baf5eef7b",
        "type": "VaultViaIrregularIp",
        "score": 27.656250000000004,
        "createTime": 1595144408000,
        "lastUpdateTime": 1595144408000,
        "audits": [
            {
                "id": "5f13f8d8e4b0ba4baf5eef79",
                "type": "VAULT_LOGON",
                "sensorType": "VAULT",
                "action": "Logon",
                "createTime": 1595144408000,
                "vaultUser": "Administrator",
                "source": {"mOriginalAddress": "17.111.13.67"},
                "cloudData": {},
            }
        ],
        "additionalData": {"station": "17.111.13.67", "reason": "ip", "vault_user": "administrator"},
        "mStatus": "OPEN",
    },
    {
        "id": "5f13f89fe4b0ba4baf5eee4b",
        "type": "VaultViaIrregularIp",
        "score": 50.656250000000004,
        "createTime": 1595144351000,
        "lastUpdateTime": 1595144351000,
        "audits": [
            {
                "id": "5f13f89fe4b0ba4baf5eee49",
                "type": "VAULT_LOGON",
                "sensorType": "VAULT",
                "action": "Logon",
                "createTime": 1595144351000,
                "vaultUser": "Administrator",
                "source": {"mOriginalAddress": "17.111.13.67"},
                "cloudData": {},
            }
        ],
        "additionalData": {"station": "17.111.13.67", "reason": "ip", "vault_user": "administrator"},
        "mStatus": "OPEN",
    },
    {
        "id": "5f13f861e4b0ba4baf5eed1c",
        "type": "VaultViaIrregularIp",
        "score": 27.656250000000004,
        "createTime": 1595144289000,
        "lastUpdateTime": 1595144289000,
        "audits": [
            {
                "id": "5f13f861e4b0ba4baf5eed1a",
                "type": "VAULT_LOGON",
                "sensorType": "VAULT",
                "action": "Logon",
                "createTime": 1595144289000,
                "vaultUser": "Administrator",
                "source": {"mOriginalAddress": "17.111.13.67"},
                "cloudData": {},
            }
        ],
        "additionalData": {"station": "17.111.13.67", "reason": "ip", "vault_user": "administrator"},
        "mStatus": "OPEN",
    },
    {
        "id": "5f13f824e4b0ba4baf5eebf8",
        "type": "VaultViaIrregularIp",
        "score": 27.656250000000004,
        "createTime": 1595144228000,
        "lastUpdateTime": 1595144228000,
        "audits": [
            {
                "id": "5f13f824e4b0ba4baf5eebf6",
                "type": "VAULT_LOGON",
                "sensorType": "VAULT",
                "action": "Logon",
                "createTime": 1595144228000,
                "vaultUser": "Administrator",
                "source": {"mOriginalAddress": "17.111.13.67"},
                "cloudData": {},
            }
        ],
        "additionalData": {"station": "17.111.13.67", "reason": "ip", "vault_user": "administrator"},
        "mStatus": "OPEN",
    },
    {
        "id": "5f13f7e8e4b0ba4baf5eead5",
        "type": "VaultViaIrregularIp",
        "score": 27.656250000000004,
        "createTime": 1595144168000,
        "lastUpdateTime": 1595144168000,
        "audits": [
            {
                "id": "5f13f7e8e4b0ba4baf5eead3",
                "type": "VAULT_LOGON",
                "sensorType": "VAULT",
                "action": "Logon",
                "createTime": 1595144168000,
                "vaultUser": "Administrator",
                "source": {"mOriginalAddress": "17.111.13.67"},
                "cloudData": {},
            }
        ],
        "additionalData": {"station": "17.111.13.67", "reason": "ip", "vault_user": "administrator"},
        "mStatus": "OPEN",
    },
    {
        "id": "5f13f7ade4b0ba4baf5ee9b0",
        "type": "VaultViaIrregularIp",
        "score": 98.656250000000004,
        "createTime": 1595144109000,
        "lastUpdateTime": 1595144109000,
        "audits": [
            {
                "id": "5f13f7ade4b0ba4baf5ee9ad",
                "type": "VAULT_LOGON",
                "sensorType": "VAULT",
                "action": "Logon",
                "createTime": 1595144109000,
                "vaultUser": "Administrator",
                "source": {"mOriginalAddress": "17.111.13.67"},
                "cloudData": {},
            }
        ],
        "additionalData": {"station": "17.111.13.67", "reason": "ip", "vault_user": "administrator"},
        "mStatus": "OPEN",
    },
    {
        "id": "5f13f770e4b0ba4baf5ee890",
        "type": "VaultViaIrregularIp",
        "score": 27.656250000000004,
        "createTime": 1595144048000,
        "lastUpdateTime": 1595144048000,
        "audits": [
            {
                "id": "5f13f770e4b0ba4baf5ee88e",
                "type": "VAULT_LOGON",
                "sensorType": "VAULT",
                "action": "Logon",
                "createTime": 1595144048000,
                "vaultUser": "Administrator",
                "source": {"mOriginalAddress": "17.111.13.67"},
                "cloudData": {},
            }
        ],
        "additionalData": {"station": "17.111.13.67", "reason": "ip", "vault_user": "administrator"},
        "mStatus": "OPEN",
    },
]
