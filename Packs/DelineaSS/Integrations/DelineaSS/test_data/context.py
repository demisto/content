import collections

Credentials = collections.namedtuple('Credentials', ['name', 'user', 'password'])
GET_PASSWORD_BY_ID_CONTEXT = {
    'Delinea.Secret.Password(val.secret_password && val.secret_password == obj.secret_password)': {
        "Delinea": {
            "Secret": {
                "Password": "test00111"
            }
        }
    }
}

GET_USERNAME_BY_ID_CONTENT = {
    'Delinea.Secret.Username(val.secret_username && val.secret_username == obj.secret_username)': {
        "Delinea": {
            "Secret": {
                "Username": "andy"
            }
        }
    }
}

SECRET_GET_CONTENT = {
    'Delinea.Secret(val.secret && val.secret == obj.secret)': {
        'id': 4,
        'name': 'g1-machine',
        'secretTemplateId': 6007,
        'folderId': -1,
        'active': True,
        'items': [
            {
                'itemId': 13,
                'fileAttachmentId': None,
                'filename': None,
                'itemValue': '192.168.100.1',
                'fieldId': 108,
                'fieldName': 'Machine',
                'slug': 'machine',
                'fieldDescription': 'The Server or Location of the Unix Machine.',
                'isFile': False,
                'isNotes': False,
                'isPassword': False
            },
            {
                'itemId': 14,
                'fileAttachmentId': None,
                'filename': None,
                'itemValue': 'andy',
                'fieldId': 111,
                'fieldName': 'Username',
                'slug': 'username',
                'fieldDescription': 'The Unix Machine Username.',
                'isFile': False,
                'isNotes': False,
                'isPassword': False
            },
            {
                'itemId': 15,
                'fileAttachmentId': None,
                'filename': None,
                'itemValue': 'test00111',
                'fieldId': 110,
                'fieldName': 'Password',
                'slug': 'password',
                'fieldDescription': 'The password of the Unix Machine.',
                'isFile': False,
                'isNotes': False,
                'isPassword': True
            },
            {
                'itemId': 16,
                'fileAttachmentId': None,
                'filename': None,
                'itemValue': '',
                'fieldId': 109,
                'fieldName': 'Notes',
                'slug': 'notes',
                'fieldDescription': 'Any additional notes.',
                'isFile': False,
                'isNotes': True,
                'isPassword': False
            },
            {
                'itemId': 17,
                'fileAttachmentId': None,
                'filename': None,
                'itemValue': '*** Not Valid For Display ***',
                'fieldId': 189,
                'fieldName': 'Private Key',
                'slug': 'private-key',
                'fieldDescription': 'The SSH private key.',
                'isFile': True, 'isNotes': False,
                'isPassword': False
            },
            {
                'itemId': 18,
                'fileAttachmentId': None,
                'filename': None,
                'itemValue': '',
                'fieldId': 190,
                'fieldName': 'Private Key Passphrase',
                'slug': 'private-key-passphrase',
                'fieldDescription': 'The passphrase for decrypting the SSH private key.',
                'isFile': False,
                'isNotes': False,
                'isPassword': True
            }
        ],
        'launcherConnectAsSecretId': -1,
        'checkOutMinutesRemaining': 0,
        'checkedOut': False,
        'checkOutUserDisplayName': '',
        'checkOutUserId': -1,
        'isRestricted': False,
        'isOutOfSync': False,
        'outOfSyncReason': '',
        'autoChangeEnabled': False,
        'autoChangeNextPassword': 'Test000',
        'requiresApprovalForAccess': False,
        'requiresComment': False,
        'checkOutEnabled': False,
        'checkOutIntervalMinutes': -1,
        'checkOutChangePasswordEnabled': False,
        'accessRequestWorkflowMapId': -1,
        'proxyEnabled': False,
        'sessionRecordingEnabled': False,
        'restrictSshCommands': False,
        'allowOwnersUnrestrictedSshCommands': False,
        'isDoubleLock': False,
        'doubleLockId': -1,
        'enableInheritPermissions': False,
        'passwordTypeWebScriptId': -1,
        'siteId': 1,
        'enableInheritSecretPolicy': False,
        'secretPolicyId': -1,
        'lastHeartBeatStatus': 'Success',
        'lastHeartBeatCheck': '2020-11-03T16:20:34.917',
        'failedPasswordChangeAttempts': 160,
        'lastPasswordChangeAttempt': '2020-11-10T10:32:59.217',
        'secretTemplateName': 'Unix Account (SSH)',
        'responseCodes': []
    }
}

SECRET_PASSWORD_UPDATE_CONTEXT = {
    'Delinea.Secret.Newpassword(val.secret_newpassword && val.secret_newpassword == obj.secret_newpassword)': {
        "Delinea": {
            "Secret": {
                "Newpassword": "NEWPASSWORD1"
            }
        }
    }
}

SECRET_CHECKOUT_CONTEXT = {
    'Delinea.Secret.Checkout(val.secret_checkout && val.secret_checkout == obj.secret_checkout)': {
        "responseCodes": []
    }
}

SECRET_CHECKIN_CONTEXT = {
    "Delinea.Secret.Checkin(val.secret_checkin && val.secret_checkin == obj.secret_checkin)": {
        "active": "true",
        "autoChangeEnabled": "false",
        "checkOutEnabled": "true",
        "checkedOut": "false",
        "createDate": "2020-11-02T18:06:07.357",
        "daysUntilExpiration": "null",
        "doubleLockEnabled": "false",
        "extendedFields": "null",
        "folderId": -1,
        "hidePassword": "false",
        "id": 4,
        "inheritsPermissions": "false",
        "isOutOfSync": "false",
        "isRestricted": "true",
        "lastAccessed": "null",
        "lastHeartBeatStatus": "Success",
        "lastPasswordChangeAttempt": "2020-11-11T08:49:59.873",
        "name": "g1-machine",
        "outOfSyncReason": "",
        "requiresApproval": "false",
        "requiresComment": "false",
        "responseCodes": "null",
        "secretTemplateId": 6007,
        "secretTemplateName": "Unix Account (SSH)",
        "siteId": 1
    }
}

SECRET_DELETE_CONTEXT = {
    "Delinea.Secret.Deleted(val.delete && val.delete == obj.delete)": {
        "id": 9,
        "objectType": "Secret",
        "responseCodes": []
    }
}

FOLDER_CREATE_CONTEXT = {
    "Delinea.Folder.Create(val.folder && val.folder == obj.folder)": {
        "childFolders": "null",
        "folderName": "xsoarFolderTest3",
        "folderPath": "\\Personal Folders\\XSOAR integration\\xsoarFolderTest3",
        "folderTypeId": 1,
        "id": 7,
        "inheritPermissions": "false",
        "inheritSecretPolicy": "false",
        "parentFolderId": 3,
        "secretPolicyId": -1,
        "secretTemplates": "null"
    }
}

FOLDER_DELETE_CONTEXT = {
    "Delinea.Folder.Delete(val.folder && val.folder == obj.folder)": {
        "id": 11,
        "objectType": "Folder",
        "responseCodes": []
    }
}

FOLDER_UPDATE_CONTEXT = {
    "Delinea.Folder.Update(val.folder && val.folder == obj.folder)": {
        "childFolders": "null",
        "folderName": "xsoarTF3New",
        "folderPath": "\\Personal Folders\\XSOAR integration\\xsoarTF3New",
        "folderTypeId": 1,
        "id": 12,
        "inheritPermissions": "false",
        "inheritSecretPolicy": "false",
        "parentFolderId": 3,
        "secretPolicyId": -1,
        "secretTemplates": "null"
    }
}

USER_DELETE_CONTEXT = {
    "Delinea.User.Delete(val.user && val.user == obj.user)": {
        "id": 5,
        "objectType": "User",
        "responseCodes": []
    }
}

SECRET_CREATE_CONTEXT = {
    "Delinea.Secret.Create(val.secret && val.secret == obj.secret)": {
        "accessRequestWorkflowMapId": -1,
        "active": "true",
        "allowOwnersUnrestrictedSshCommands": "false",
        "autoChangeEnabled": "false",
        "autoChangeNextPassword": "null",
        "checkOutChangePasswordEnabled": "false",
        "checkOutEnabled": "true",
        "checkOutIntervalMinutes": -1,
        "checkOutMinutesRemaining": 0,
        "checkOutUserDisplayName": "",
        "checkOutUserId": 0,
        "checkedOut": "false",
        "doubleLockId": 0,
        "enableInheritPermissions": "true",
        "enableInheritSecretPolicy": "false",
        "failedPasswordChangeAttempts": 0,
        "folderId": 3,
        "id": 5,
        "isDoubleLock": "false",
        "isOutOfSync": "false",
        "isRestricted": "true",
        "items": [
            {
                "fieldDescription": "Any additional notes.",
                "fieldId": 84,
                "fieldName": "Notes",
                "fileAttachmentId": "null",
                "filename": "null",
                "isFile": "false",
                "isNotes": "true",
                "isPassword": "false",
                "itemId": 22,
                "itemValue": "",
                "slug": "notes"
            }
        ],
        "lastHeartBeatCheck": "0001-01-01T00:00:00",
        "lastHeartBeatStatus": "Pending",
        "lastPasswordChangeAttempt": "0001-01-01T00:00:00",
        "launcherConnectAsSecretId": -1,
        "name": "xsoarSecret",
        "outOfSyncReason": "",
        "passwordTypeWebScriptId": -1,
        "proxyEnabled": "false",
        "requiresApprovalForAccess": "false",
        "requiresComment": "false",
        "responseCodes": [],
        "restrictSshCommands": "false",
        "secretPolicyId": -1,
        "secretTemplateId": 6003,
        "secretTemplateName": "Windows Account",
        "sessionRecordingEnabled": "false",
        "siteId": 1
    }
}

USER_CREATE_CONTEXT = {
    "Delinea.User.Create(val.user && val.user == obj.user)": {
        "adAccountExpires": "0001-01-01T00:00:00",
        "adGuid": "null",
        "created": "2022-06-01T08:31:15.275Z",
        "dateOptionId": -1,
        "displayName": "UserOne",
        "domainId": -1,
        "duoTwoFactor": "false",
        "emailAddress": "null",
        "enabled": "true",
        "externalUserSource": "None",
        "fido2TwoFactor": "false",
        "id": 29,
        "ipAddressRestrictions": "null",
        "isApplicationAccount": "false",
        "isEmailCopiedFromAD": "false",
        "isEmailVerified": "false",
        "isLockedOut": "false",
        "lastLogin": "0001-01-01T00:00:00",
        "lastSessionActivity": "null",
        "lockOutReason": "null",
        "lockOutReasonDescription": "null",
        "loginFailures": 0,
        "mustVerifyEmail": "false",
        "oathTwoFactor": "false",
        "oathVerified": "false",
        "passwordLastChanged": "0001-01-01T00:00:00",
        "personalGroupId": 0,
        "radiusTwoFactor": "false",
        "radiusUserName": "null",
        "resetSessionStarted": "0001-01-01T00:00:00",
        "slackId": "null",
        "timeOptionId": -1,
        "twoFactor": "false",
        "unixAuthenticationMethod": "Password",
        "userLcid": 0,
        "userName": "UserOne",
        "verifyEmailSentDate": "0001-01-01T00:00:00"
    }
}

USER_UPDATE_CONTEXT = {
    "Delinea.User.Update(val.user && val.user == obj.user)": {
        "unixAuthenticationMethod": "Password",
        "enabled": "true",
        "passwordLastChanged": "0001-01-01T00:00:00",
        "isEmailCopiedFromAD": "false",
        "isApplicationAccount": "false",
        "lockOutReason": "null",
        "created": "2022-06-01T08:09:39",
        "radiusUserName": "UserOne",
        "radiusTwoFactor": "false",
        "verifyEmailSentDate": "0001-01-01T00:00:00",
        "adAccountExpires": "0001-01-01T00:00:00",
        "slackId": "null",
        "adGuid": "null",
        "displayName": "myTestUser",
        "oathVerified": "false",
        "lastSessionActivity": "null",
        "externalUserSource": "None",
        "loginFailures": 0,
        "lastLogin": "0001-01-01T00:00:00",
        "ipAddressRestrictions": "null",
        "oathTwoFactor": "false",
        "lockOutReasonDescription": "null",
        "userName": "UserOne",
        "fido2TwoFactor": "false",
        "emailAddress": "null",
        "resetSessionStarted": "0001-01-01T00:00:00",
        "mustVerifyEmail": "false",
        "isEmailVerified": "false",
        "personalGroupId": 0,
        "isLockedOut": "false",
        "id": 28,
        "twoFactor": "false",
        "duoTwoFactor": "false",
        "timeOptionId": -1,
        "userLcid": 0,
        "dateOptionId": -1,
        "domainId": -1
    }
}

SECRET_RPC_CHANGE_PASSWORD_CONTEXT = {
    'Delinea.Secret.ChangePassword(val.secret && val.secret == obj.secret)': {
        "id": 3482,
        "name": "test123",
        "secretTemplateId": 6001,
        "secretTemplateName": "Active Directory Account",
        "folderId": 198,
        "siteId": 1,
        "active": "true",
        "checkedOut": "false",
        "isRestricted": "false",
        "isOutOfSync": "false",
        "outOfSyncReason": "",
        "lastHeartBeatStatus": "Pending",
        "lastPasswordChangeAttempt": "0001-01-01T00:00:00",
        "responseCodes": "null",
        "lastAccessed": "null",
        "extendedFields": "null",
        "checkOutEnabled": "false",
        "autoChangeEnabled": "false",
        "doubleLockEnabled": "false",
        "requiresApproval": "false",
        "requiresComment": "false",
        "inheritsPermissions": "true",
        "hidePassword": "false",
        "createDate": "2022-08-30T10:32:14.407",
        "daysUntilExpiration": "null",
        "hasLauncher": "false"
    }
}

SECRET_GET_CREDENTIALS_CONTEXT = {
    'Delinea.Secret.Fetch.Credentials(val.credentials && val.credentials == obj.credentials)': [
        {
            'name': '4',
            'password': 'password',
            'user': 'user'
        }
    ]

}

SECRET_SEARCH_NAME_CONTEXT = {
    'Delinea.Secret.Id(val.search_id && val.search_id == obj.search_id)': [
        3564,
        3566,
        4241
    ]
}


SECRET_SEARCH_CONTEXT = {
    'Delinea.Secret.Secret(val.search_secret && val.search_secret == obj.search_secret)': [
        967,
        966
    ]
}


FOLDER_SEARCH_CONTEXT = {
    'Delinea.Folder.Id(val.folder_id && val.folder_id == obj.folder_id)': [
        145
    ]
}

USER_SEARCH_CONTEXT = {
    'Delinea.User.Search(val.user && val.user == obj.user)': [
        {
            "id": 236,
            "userName": "adil@jim",
            "displayName": "Adil",
            "lastLogin": "2023-04-11T23:09:56",
            "created": "2023-04-11T22:18:05",
            "enabled": True,
            "loginFailures": 0,
            "emailAddress": "dummyemail",
            "domainId": -1,
            "domainName": None,
            "isLockedOut": False,
            "isApplicationAccount": False,
            "twoFactorMethod": "None",
            "externalUserSource": "Platform",
            "platformIntegrationType": "Native"
        }
    ]

}
