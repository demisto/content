ADD_USER_CONTEXT = {
  "CyberArk.Users.123(val.id == obj.id)": {
    "authenticationMethod": [
      "AuthTypePass"
    ],
    "businessAddress": {
      "workCity": "",
      "workCountry": "",
      "workState": "",
      "workStreet": "",
      "workZip": ""
    },
    "changePassOnNextLogon": True,
    "componentUser": False,
    "description": "new user for test",
    "distinguishedName": "",
    "enableUser": True,
    "expiryDate": -62135578800,
    "groupsMembership": [],
    "id": 123,
    "internet": {
      "businessEmail": "usertest@test.com",
      "homeEmail": "",
      "homePage": "",
      "otherEmail": ""
    },
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
      "zip": ""
    },
    "phones": {
      "businessNumber": "",
      "cellularNumber": "",
      "faxNumber": "",
      "homeNumber": "",
      "pagerNumber": ""
    },
    "source": "CyberArk",
    "suspended": False,
    "unAuthorizedInterfaces": [],
    "userType": "EPVUser",
    "username": "TestUser",
    "vaultAuthorization": []
  }
}

UPDATE_USER_CONTEXT = {
  "CyberArk.Users.123(val.id == obj.id)": {
    "authenticationMethod": [
      "AuthTypePass"
    ],
    "businessAddress": {
      "workCity": "",
      "workCountry": "",
      "workState": "",
      "workStreet": "",
      "workZip": ""
    },
    "changePassOnNextLogon": True,
    "componentUser": False,
    "description": "updated description",
    "distinguishedName": "",
    "enableUser": True,
    "expiryDate": -62135578800,
    "groupsMembership": [],
    "id": 123,
    "internet": {
      "businessEmail": "update@test.com",
      "homeEmail": "",
      "homePage": "",
      "otherEmail": ""
    },
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
      "zip": ""
    },
    "phones": {
      "businessNumber": "",
      "cellularNumber": "",
      "faxNumber": "",
      "homeNumber": "",
      "pagerNumber": ""
    },
    "source": "CyberArk",
    "suspended": False,
    "unAuthorizedInterfaces": [],
    "userType": "EPVUser",
    "username": "TestUser1",
    "vaultAuthorization": []
  }
}

GET_USERS_CONTEXT = {
  "CyberArk.Users(val.id == obj.id)": [
    {
      "componentUser": False,
      "id": 2,
      "location": "\\",
      "personalDetails": {
        "firstName": "",
        "lastName": "",
        "middleName": ""
      },
      "source": "CyberArk",
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
        "ActivateUsers"
      ]
    },
    {
      "componentUser": False,
      "id": 3,
      "location": "\\",
      "personalDetails": {
        "firstName": "",
        "lastName": "",
        "middleName": ""
      },
      "source": "CyberArk",
      "userType": "Built-InAdmins",
      "username": "Auditor",
      "vaultAuthorization": [
        "AuditUsers"
      ]
    }
  ]
}

ADD_SAFE_CONTEXT = {
  "CyberArk.Safes.TestSafe(val.SafeName == obj.SafeName)": {
    "AutoPurgeEnabled": False,
    "Description": "safe for tests",
    "Location": "\\",
    "ManagingCPM": "",
    "NumberOfDaysRetention": 100,
    "NumberOfVersionsRetention": None,
    "OLACEnabled": True,
    "SafeName": "TestSafe"
  }
}

UPDATE_SAFE_CONTEXT = {
  "CyberArk.Safes.TestSafe(val.SafeName == obj.SafeName)": {
    "AutoPurgeEnabled": False,
    "Description": "UpdatedSafe",
    "Location": "\\",
    "ManagingCPM": "",
    "NumberOfDaysRetention": 150,
    "NumberOfVersionsRetention": None,
    "OLACEnabled": True,
    "SafeName": "UpdatedName"
  }
}

GET_SAFE_BY_NAME_CONTEXT = {
  "CyberArk.Safes.TestSafe(val.SafeName == obj.SafeName)": {
    "AutoPurgeEnabled": False,
    "Description": "safe for tests",
    "Location": "\\",
    "ManagingCPM": "",
    "NumberOfDaysRetention": 100,
    "NumberOfVersionsRetention": None,
    "OLACEnabled": True,
    "SafeName": "TestSafe"
  }
}

GET_LIST_SAFES_CONTEXT = {
  "CyberArk.Safes(val.SafeName == obj.SafeName)": [
    {
      "Description": "",
      "Location": "\\",
      "SafeName": "VaultInternal",
      "SafeUrlId": "VaultInternal"
    },
    {
      "Description": "",
      "Location": "\\",
      "SafeName": "Notification Engine",
      "SafeUrlId": "Notification%20Engine"
    }]}

ADD_SAFE_MEMBER_CONTEXT = {
  "CyberArk.TestSafe.TestUser(val.TestUser == obj.TestUser)": {
    "MemberName": "TestUser",
    "MembershipExpirationDate": "",
    "Permissions": [
      {
        "Key": "UseAccounts",
        "Value": False
      },
      {
        "Key": "RetrieveAccounts",
        "Value": False
      },
      {
        "Key": "ListAccounts",
        "Value": False
      },
      {
        "Key": "AddAccounts",
        "Value": False
      },
      {
        "Key": "UpdateAccountContent",
        "Value": False
      },
      {
        "Key": "UpdateAccountProperties",
        "Value": False
      },
      {
        "Key": "InitiateCPMAccountManagementOperations",
        "Value": False
      },
      {
        "Key": "SpecifyNextAccountContent",
        "Value": False
      },
      {
        "Key": "RenameAccounts",
        "Value": False
      },
      {
        "Key": "DeleteAccounts",
        "Value": False
      },
      {
        "Key": "UnlockAccounts",
        "Value": False
      },
      {
        "Key": "ManageSafe",
        "Value": False
      },
      {
        "Key": "ManageSafeMembers",
        "Value": False
      },
      {
        "Key": "BackupSafe",
        "Value": False
      },
      {
        "Key": "ViewAuditLog",
        "Value": False
      },
      {
        "Key": "ViewSafeMembers",
        "Value": False
      },
      {
        "Key": "AccessWithoutConfirmation",
        "Value": False
      },
      {
        "Key": "CreateFolders",
        "Value": False
      },
      {
        "Key": "DeleteFolders",
        "Value": False
      },
      {
        "Key": "MoveAccountsAndFolders",
        "Value": False
      },
      {
        "Key": "RequestsAuthorizationLevel",
        "Value": 0
      }
    ],
    "SearchIn": "vault"
  }
}

UPDATE_SAFE_MEMBER_CONTEXT = {
  "CyberArk.TestSafe.TestUser(val.TestUser == obj.TestUser)": {
    "MemberName": "TestUser",
    "MembershipExpirationDate": "",
    "Permissions": [
      {
        "Key": "UseAccounts",
        "Value": True
      },
      {
        "Key": "RetrieveAccounts",
        "Value": False
      },
      {
        "Key": "ListAccounts",
        "Value": False
      },
      {
        "Key": "AddAccounts",
        "Value": False
      },
      {
        "Key": "UpdateAccountContent",
        "Value": False
      },
      {
        "Key": "UpdateAccountProperties",
        "Value": False
      },
      {
        "Key": "InitiateCPMAccountManagementOperations",
        "Value": False
      },
      {
        "Key": "SpecifyNextAccountContent",
        "Value": False
      },
      {
        "Key": "RenameAccounts",
        "Value": False
      },
      {
        "Key": "DeleteAccounts",
        "Value": False
      },
      {
        "Key": "UnlockAccounts",
        "Value": False
      },
      {
        "Key": "ManageSafe",
        "Value": False
      },
      {
        "Key": "ManageSafeMembers",
        "Value": False
      },
      {
        "Key": "BackupSafe",
        "Value": False
      },
      {
        "Key": "ViewAuditLog",
        "Value": False
      },
      {
        "Key": "ViewSafeMembers",
        "Value": False
      },
      {
        "Key": "AccessWithoutConfirmation",
        "Value": False
      },
      {
        "Key": "CreateFolders",
        "Value": False
      },
      {
        "Key": "DeleteFolders",
        "Value": False
      },
      {
        "Key": "MoveAccountsAndFolders",
        "Value": False
      },
      {
        "Key": "RequestsAuthorizationLevel",
        "Value": 0
      }
    ],
    "SearchIn": "vault"
  }
}

LIST_SAFE_MEMBER_CONTEXT = {
  "CyberArk.TestSafe.Members(val.MemberName == obj.MemberName)": [
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
        "ViewSafeMembers": True
      }
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
        "ViewSafeMembers": True
      }
    }]
}

ADD_ACCOUNT_CONTEXT = {
  "CyberArk.Accounts.77_4(val.id == obj.id)": {
    "address": "/",
    "categoryModificationTime": 1594835018,
    "createdTime": 1594838456,
    "id": "77_4",
    "name": "TestAccount1",
    "platformId": "WinServerLocal",
    "safeName": "TestSafe",
    "secretManagement": {
      "automaticManagementEnabled": True,
      "lastModifiedTime": 1594824056
    },
    "secretType": "password",
    "userName": "TestUser"
  }
}

UPDATE_ACCOUNT_CONTEXT = {
  "CyberArk.Accounts.77_4(val.id == obj.id)": {
    "address": "/",
    "categoryModificationTime": 1594835018,
    "createdTime": 1594838456,
    "id": "77_4",
    "name": "NewName",
    "platformId": "WinServerLocal",
    "safeName": "TestSafe",
    "secretManagement": {
      "automaticManagementEnabled": True,
      "lastModifiedTime": 1594824056
    },
    "secretType": "password",
    "userName": "TestUser"
  }
}

GET_LIST_ACCOUNT_CONTEXT = {
  "CyberArk.Accounts(val.id == obj.id)": [
    {
      "address": "string",
      "categoryModificationTime": 1594569595,
      "createdTime": 1594573679,
      "id": "2_6",
      "name": "account1",
      "platformAccountProperties": {},
      "platformId": "Oracle",
      "safeName": "VaultInternal",
      "secretManagement": {
        "automaticManagementEnabled": True,
        "lastModifiedTime": 1594559279
      },
      "secretType": "password",
      "userName": "string"
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
        "manualManagementReason": "NoReason"
      },
      "secretType": "password",
      "userName": "vaultbind@cybr.com"
    }
  ]
}

GET_LIST_ACCOUNT_ACTIVITIES_CONTEXT = {
  "CyberArk.77_4.Activities": [
    {
      "Action": "Rename File",
      "ActionID": 124,
      "Alert": False,
      "ClientID": "PVWA",
      "Date": 1594838533,
      "MoreInfo": "NewName",
      "Reason": "",
      "User": "Administrator"
    },
    {
      "Action": "Store password",
      "ActionID": 294,
      "Alert": False,
      "ClientID": "PVWA",
      "Date": 1594838456,
      "MoreInfo": "",
      "Reason": "",
      "User": "Administrator"
    }]}
