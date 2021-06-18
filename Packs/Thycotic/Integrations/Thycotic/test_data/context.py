GET_PASSWORD_BY_ID_CONTEXT = {
    'Thycotic.Secret.Password(val.secret_password && val.secret_password == obj.secret_password)': {
        "Thycotic": {
            "Secret": {
                "Password": "test00111"
            }
        }
    }
}

GET_USERNAME_BY_ID_CONTENT = {
    'Thycotic.Secret.Username(val.secret_username && val.secret_username == obj.secret_username)': {
        "Thycotic": {
            "Secret": {
                "Username": "andy"
            }
        }
    }
}

SECRET_GET_CONTENT = {
    'Thycotic.Secret(val.secret && val.secret == obj.secret)': {
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
    'Thycotic.Secret.Newpassword(val.secret_newpassword && val.secret_newpassword == obj.secret_newpassword)': {
        "Thycotic": {
            "Secret": {
                "Newpassword": "NEWPASSWORD1"
            }
        }
    }
}

SECRET_CHECKOUT_CONTEXT = {
    'Thycotic.Secret.Checkout(val.secret_checkout && val.secret_checkout == obj.secret_checkout)': {
        "ResponseCode": "null"
    }
}

SECRET_CHECKIN_CONTEXT = {
  "Thycotic.Secret.Checkin(val.secret_checkin && val.secret_checkin == obj.secret_checkin)": {
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
    "Thycotic.Secret.Deleted(val.delete && val.delete == obj.delete)": {
        "id": 9,
        "objectType": "Secret",
        "responseCodes": []
    }
}

FOLDER_CREATE_CONTEXT = {
  "Thycotic.Folder.Create(val.folder && val.folder == obj.folder)": {
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
    "Thycotic.Folder.Delete(val.folder && val.folder == obj.folder)": {
        "id": 11,
        "objectType": "Folder",
        "responseCodes": []
    }
}

FOLDER_UPDATE_CONTEXT = {
    "Thycotic.Folder.Update(val.folder && val.folder == obj.folder)": {
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
