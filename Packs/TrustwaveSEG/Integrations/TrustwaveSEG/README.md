Trustwave SEG is a secure messaging solution that protects businesses and users from email-borne threats, including phishing, blended threats, and spam. Trustwave Secure Email Gateway also delivers improved policy enforcement and data leakage prevention.
This integration was integrated and tested with version 10 of trustwave secure email gateway.
## Configure trustwave secure email gateway in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Hostname or IP | Hostname or IP address \(localhost or 127.0.0.1\). | True |
| SEG Configuration Service Port | Used for retrieving a token for the commands. | True |
| SEG API Port | Used for accessing the API console. | True |
| User Credentials |  | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### trustwave-seg-get-version
***
Gets Trustwave version information.


#### Base Command

`trustwave-seg-get-version`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TrustwaveSEG.Version.configVersion | Number | The configuration version. | 
| TrustwaveSEG.Version.productVersion | String | The product version. | 
| TrustwaveSEG.Version.rpcInterfaceVersion | Number | The RPC interface version. | 


#### Command Example
```!trustwave-seg-get-version```

#### Context Example
```json
{
    "TrustwaveSEG": {
        "Version": {
            "configVersion": 39,
            "productVersion": "10.0.1.2030",
            "rpcInterfaceVersion": 31
        }
    }
}
```

#### Human Readable Output

>### Version Information
>|Config Version|Product Version|
>|---|---|
>| 39 | 10.0.1.2030 |


### trustwave-seg-automatic-config-backup-list
***
Returns a list of automatic configuration backups.


#### Base Command

`trustwave-seg-automatic-config-backup-list`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TrustwaveSEG.AutomaticBackupConfig.fileSize | Number | The file size of the automatic configuration backup. | 
| TrustwaveSEG.AutomaticBackupConfig.filename | String | The filename of the automatic configuration backup. | 
| TrustwaveSEG.AutomaticBackupConfig.info.backupTime | Number | The backup time of the automatic configuration backup. | 
| TrustwaveSEG.AutomaticBackupConfig.info.backupTimeStr | Date | The backup time string of the automatic configuration backup. | 
| TrustwaveSEG.AutomaticBackupConfig.info.backupType | String | The backup type of the automatic configuration backup. | 
| TrustwaveSEG.AutomaticBackupConfig.info.backupUser | String | The back up user of the automatic configuration backup. | 
| TrustwaveSEG.AutomaticBackupConfig.info.commitDescription | String | The commit description of the automatic configuration backup. | 
| TrustwaveSEG.AutomaticBackupConfig.info.commitSetId | Number | The commit set ID of the automatic configuration backup. | 
| TrustwaveSEG.AutomaticBackupConfig.info.commitUser | String | The commit user of the automatic configuration backup. | 
| TrustwaveSEG.AutomaticBackupConfig.info.configVersion | Number | The configuration version of the automatic configuration backup. | 
| TrustwaveSEG.AutomaticBackupConfig.info.containsDkimKeys | Boolean | Whether there are DomainKeys Identified Mail \(DKIM\) keys for the automatic configuration backup. | 
| TrustwaveSEG.AutomaticBackupConfig.info.productVersion | String | The product version of the automatic configuration backup. | 
| TrustwaveSEG.AutomaticBackupConfig.lastModified | Number | The date the automatic backup configuration was last modified. | 


#### Command Example
```!trustwave-seg-automatic-config-backup-list```

#### Context Example
```json
{
    "TrustwaveSEG": {
        "AutomaticBackupConfig": [
            {
                "backupTime": 1620650406,
                "backupTimeStr": "2021-05-10T12:40:06Z",
                "backupType": "full",
                "backupUser": "admin",
                "commitDescription": "Committing Marshal RBL credentials update",
                "commitSetId": 102,
                "commitUser": "admin",
                "configVersion": 39,
                "containsDkimKeys": false,
                "fileSize": 69732378,
                "filename": "MailMarshal-10.0.1-ManualBackup_10-May-2021-05-40-05",
                "info": {
                    "backupTime": 1620650406,
                    "backupTimeStr": "2021-05-10T12:40:06Z",
                    "backupType": "full",
                    "backupUser": "admin",
                    "commitDescription": "Committing Marshal RBL credentials update",
                    "commitSetId": 102,
                    "commitUser": "admin",
                    "configVersion": 39,
                    "containsDkimKeys": false,
                    "productVersion": "10.0.1.2030"
                },
                "lastModified": 1620650415,
                "productVersion": "10.0.1.2030"
            },
            {
                "backupTime": 1620601203,
                "backupTimeStr": "2021-05-09T23:00:03Z",
                "backupType": "full",
                "backupUser": "admin",
                "commitDescription": "Files updates automatically applied.",
                "commitSetId": 100,
                "commitUser": "admin",
                "configVersion": 39,
                "containsDkimKeys": false,
                "fileSize": 69732255,
                "filename": "MailMarshal-10.0.1-AutomaticBackup_09-May-2021-16-00-00",
                "info": {
                    "backupTime": 1620601203,
                    "backupTimeStr": "2021-05-09T23:00:03Z",
                    "backupType": "full",
                    "backupUser": "admin",
                    "commitDescription": "Files updates automatically applied.",
                    "commitSetId": 100,
                    "commitUser": "admin",
                    "configVersion": 39,
                    "containsDkimKeys": false,
                    "productVersion": "10.0.1.2030"
                },
                "lastModified": 1620601213,
                "productVersion": "10.0.1.2030"
            },
            {
                "backupTime": 1620514801,
                "backupTimeStr": "2021-05-08T23:00:01Z",
                "backupType": "full",
                "backupUser": "admin",
                "commitDescription": "Files updates automatically applied.",
                "commitSetId": 100,
                "commitUser": "admin",
                "configVersion": 39,
                "containsDkimKeys": false,
                "fileSize": 69732256,
                "filename": "MailMarshal-10.0.1-AutomaticBackup_08-May-2021-16-00-00",
                "info": {
                    "backupTime": 1620514801,
                    "backupTimeStr": "2021-05-08T23:00:01Z",
                    "backupType": "full",
                    "backupUser": "admin",
                    "commitDescription": "Files updates automatically applied.",
                    "commitSetId": 100,
                    "commitUser": "admin",
                    "configVersion": 39,
                    "containsDkimKeys": false,
                    "productVersion": "10.0.1.2030"
                },
                "lastModified": 1620514812,
                "productVersion": "10.0.1.2030"
            },
            {
                "backupTime": 1620428401,
                "backupTimeStr": "2021-05-07T23:00:01Z",
                "backupType": "full",
                "backupUser": "admin",
                "commitDescription": "Files updates automatically applied.",
                "commitSetId": 100,
                "commitUser": "admin",
                "configVersion": 39,
                "containsDkimKeys": false,
                "fileSize": 69732256,
                "filename": "MailMarshal-10.0.1-AutomaticBackup_07-May-2021-16-00-00",
                "info": {
                    "backupTime": 1620428401,
                    "backupTimeStr": "2021-05-07T23:00:01Z",
                    "backupType": "full",
                    "backupUser": "admin",
                    "commitDescription": "Files updates automatically applied.",
                    "commitSetId": 100,
                    "commitUser": "admin",
                    "configVersion": 39,
                    "containsDkimKeys": false,
                    "productVersion": "10.0.1.2030"
                },
                "lastModified": 1620428412,
                "productVersion": "10.0.1.2030"
            },
            {
                "backupTime": 1620342000,
                "backupTimeStr": "2021-05-06T23:00:00Z",
                "backupType": "full",
                "backupUser": "admin",
                "commitDescription": "Files updates automatically applied.",
                "commitSetId": 99,
                "commitUser": "admin",
                "configVersion": 39,
                "containsDkimKeys": false,
                "fileSize": 69728288,
                "filename": "MailMarshal-10.0.1-AutomaticBackup_06-May-2021-16-00-00",
                "info": {
                    "backupTime": 1620342000,
                    "backupTimeStr": "2021-05-06T23:00:00Z",
                    "backupType": "full",
                    "backupUser": "admin",
                    "commitDescription": "Files updates automatically applied.",
                    "commitSetId": 99,
                    "commitUser": "admin",
                    "configVersion": 39,
                    "containsDkimKeys": false,
                    "productVersion": "10.0.1.2030"
                },
                "lastModified": 1620342009,
                "productVersion": "10.0.1.2030"
            },
            {
                "backupTime": 1620300775,
                "backupTimeStr": "2021-05-06T11:32:55Z",
                "backupType": "full",
                "backupUser": "admin",
                "commitDescription": "Committing Marshal RBL credentials update",
                "commitSetId": 98,
                "commitUser": "admin",
                "configVersion": 39,
                "containsDkimKeys": false,
                "fileSize": 69723684,
                "filename": "MailMarshal-10.0.1-ManualBackup_06-May-2021-04-32-55",
                "info": {
                    "backupTime": 1620300775,
                    "backupTimeStr": "2021-05-06T11:32:55Z",
                    "backupType": "full",
                    "backupUser": "admin",
                    "commitDescription": "Committing Marshal RBL credentials update",
                    "commitSetId": 98,
                    "commitUser": "admin",
                    "configVersion": 39,
                    "containsDkimKeys": false,
                    "productVersion": "10.0.1.2030"
                },
                "lastModified": 1620300784,
                "productVersion": "10.0.1.2030"
            },
            {
                "backupTime": 1620285980,
                "backupTimeStr": "2021-05-06T07:26:20Z",
                "backupType": "full",
                "backupUser": "admin",
                "commitDescription": "Committing Marshal RBL credentials update",
                "commitSetId": 96,
                "commitUser": "admin",
                "configVersion": 39,
                "containsDkimKeys": false,
                "fileSize": 69723497,
                "filename": "MailMarshal-10.0.1-ManualBackup_06-May-2021-00-26-20",
                "info": {
                    "backupTime": 1620285980,
                    "backupTimeStr": "2021-05-06T07:26:20Z",
                    "backupType": "full",
                    "backupUser": "admin",
                    "commitDescription": "Committing Marshal RBL credentials update",
                    "commitSetId": 96,
                    "commitUser": "admin",
                    "configVersion": 39,
                    "containsDkimKeys": false,
                    "productVersion": "10.0.1.2030"
                },
                "lastModified": 1620285989,
                "productVersion": "10.0.1.2030"
            },
            {
                "backupTime": 1620285625,
                "backupTimeStr": "2021-05-06T07:20:25Z",
                "backupType": "full",
                "backupUser": "admin",
                "commitDescription": "Committing Marshal RBL credentials update",
                "commitSetId": 94,
                "commitUser": "admin",
                "configVersion": 39,
                "containsDkimKeys": false,
                "fileSize": 69723673,
                "filename": "MailMarshal-10.0.1-ManualBackup_06-May-2021-00-20-25",
                "info": {
                    "backupTime": 1620285625,
                    "backupTimeStr": "2021-05-06T07:20:25Z",
                    "backupType": "full",
                    "backupUser": "admin",
                    "commitDescription": "Committing Marshal RBL credentials update",
                    "commitSetId": 94,
                    "commitUser": "admin",
                    "configVersion": 39,
                    "containsDkimKeys": false,
                    "productVersion": "10.0.1.2030"
                },
                "lastModified": 1620285634,
                "productVersion": "10.0.1.2030"
            },
            {
                "backupTime": 1620283437,
                "backupTimeStr": "2021-05-06T06:43:57Z",
                "backupType": "full",
                "backupUser": "admin",
                "commitDescription": "Committing Marshal RBL credentials update",
                "commitSetId": 93,
                "commitUser": "admin",
                "configVersion": 39,
                "containsDkimKeys": false,
                "fileSize": 69723593,
                "filename": "MailMarshal-10.0.1-ManualBackup_05-May-2021-23-43-56",
                "info": {
                    "backupTime": 1620283437,
                    "backupTimeStr": "2021-05-06T06:43:57Z",
                    "backupType": "full",
                    "backupUser": "admin",
                    "commitDescription": "Committing Marshal RBL credentials update",
                    "commitSetId": 93,
                    "commitUser": "admin",
                    "configVersion": 39,
                    "containsDkimKeys": false,
                    "productVersion": "10.0.1.2030"
                },
                "lastModified": 1620283446,
                "productVersion": "10.0.1.2030"
            },
            {
                "backupTime": 1620283281,
                "backupTimeStr": "2021-05-06T06:41:21Z",
                "backupType": "full",
                "backupUser": "admin",
                "commitDescription": "Committing Marshal RBL credentials update",
                "commitSetId": 92,
                "commitUser": "admin",
                "configVersion": 39,
                "containsDkimKeys": false,
                "fileSize": 69723594,
                "filename": "MailMarshal-10.0.1-ManualBackup_05-May-2021-23-41-20",
                "info": {
                    "backupTime": 1620283281,
                    "backupTimeStr": "2021-05-06T06:41:21Z",
                    "backupType": "full",
                    "backupUser": "admin",
                    "commitDescription": "Committing Marshal RBL credentials update",
                    "commitSetId": 92,
                    "commitUser": "admin",
                    "configVersion": 39,
                    "containsDkimKeys": false,
                    "productVersion": "10.0.1.2030"
                },
                "lastModified": 1620283289,
                "productVersion": "10.0.1.2030"
            },
            {
                "backupTime": 1620255600,
                "backupTimeStr": "2021-05-05T23:00:00Z",
                "backupType": "full",
                "backupUser": "admin",
                "commitDescription": "Committing Marshal RBL credentials update",
                "commitSetId": 89,
                "commitUser": "admin",
                "configVersion": 39,
                "containsDkimKeys": false,
                "fileSize": 69723546,
                "filename": "MailMarshal-10.0.1-AutomaticBackup_05-May-2021-16-00-00",
                "info": {
                    "backupTime": 1620255600,
                    "backupTimeStr": "2021-05-05T23:00:00Z",
                    "backupType": "full",
                    "backupUser": "admin",
                    "commitDescription": "Committing Marshal RBL credentials update",
                    "commitSetId": 89,
                    "commitUser": "admin",
                    "configVersion": 39,
                    "containsDkimKeys": false,
                    "productVersion": "10.0.1.2030"
                },
                "lastModified": 1620255609,
                "productVersion": "10.0.1.2030"
            },
            {
                "backupTime": 1620217869,
                "backupTimeStr": "2021-05-05T12:31:09Z",
                "backupType": "full",
                "backupUser": "admin",
                "commitDescription": "Committing Marshal RBL credentials update",
                "commitSetId": 88,
                "commitUser": "admin",
                "configVersion": 39,
                "containsDkimKeys": false,
                "fileSize": 69723589,
                "filename": "MailMarshal-10.0.1-ManualBackup_05-May-2021-05-31-09",
                "info": {
                    "backupTime": 1620217869,
                    "backupTimeStr": "2021-05-05T12:31:09Z",
                    "backupType": "full",
                    "backupUser": "admin",
                    "commitDescription": "Committing Marshal RBL credentials update",
                    "commitSetId": 88,
                    "commitUser": "admin",
                    "configVersion": 39,
                    "containsDkimKeys": false,
                    "productVersion": "10.0.1.2030"
                },
                "lastModified": 1620217878,
                "productVersion": "10.0.1.2030"
            },
            {
                "backupTime": 1620217689,
                "backupTimeStr": "2021-05-05T12:28:09Z",
                "backupType": "full",
                "backupUser": "admin",
                "commitDescription": "Committing Marshal RBL credentials update",
                "commitSetId": 86,
                "commitUser": "admin",
                "configVersion": 39,
                "containsDkimKeys": false,
                "fileSize": 69723490,
                "filename": "MailMarshal-10.0.1-ManualBackup_05-May-2021-05-28-09",
                "info": {
                    "backupTime": 1620217689,
                    "backupTimeStr": "2021-05-05T12:28:09Z",
                    "backupType": "full",
                    "backupUser": "admin",
                    "commitDescription": "Committing Marshal RBL credentials update",
                    "commitSetId": 86,
                    "commitUser": "admin",
                    "configVersion": 39,
                    "containsDkimKeys": false,
                    "productVersion": "10.0.1.2030"
                },
                "lastModified": 1620217698,
                "productVersion": "10.0.1.2030"
            },
            {
                "backupTime": 1620217531,
                "backupTimeStr": "2021-05-05T12:25:31Z",
                "backupType": "full",
                "backupUser": "admin",
                "commitDescription": "Files updates automatically applied.",
                "commitSetId": 84,
                "commitUser": "admin",
                "configVersion": 39,
                "containsDkimKeys": false,
                "fileSize": 69723751,
                "filename": "MailMarshal-10.0.1-ManualBackup_05-May-2021-05-25-31",
                "info": {
                    "backupTime": 1620217531,
                    "backupTimeStr": "2021-05-05T12:25:31Z",
                    "backupType": "full",
                    "backupUser": "admin",
                    "commitDescription": "Files updates automatically applied.",
                    "commitSetId": 84,
                    "commitUser": "admin",
                    "configVersion": 39,
                    "containsDkimKeys": false,
                    "productVersion": "10.0.1.2030"
                },
                "lastModified": 1620217540,
                "productVersion": "10.0.1.2030"
            },
            {
                "backupTime": 1620217310,
                "backupTimeStr": "2021-05-05T12:21:50Z",
                "backupType": "full",
                "backupUser": "admin",
                "commitDescription": "Files updates automatically applied.",
                "commitSetId": 84,
                "commitUser": "admin",
                "configVersion": 39,
                "containsDkimKeys": false,
                "fileSize": 69723751,
                "filename": "MailMarshal-10.0.1-ManualBackup_05-May-2021-05-21-50",
                "info": {
                    "backupTime": 1620217310,
                    "backupTimeStr": "2021-05-05T12:21:50Z",
                    "backupType": "full",
                    "backupUser": "admin",
                    "commitDescription": "Files updates automatically applied.",
                    "commitSetId": 84,
                    "commitUser": "admin",
                    "configVersion": 39,
                    "containsDkimKeys": false,
                    "productVersion": "10.0.1.2030"
                },
                "lastModified": 1620217319,
                "productVersion": "10.0.1.2030"
            },
            {
                "backupTime": 1620217071,
                "backupTimeStr": "2021-05-05T12:17:51Z",
                "backupType": "full",
                "backupUser": "admin",
                "commitDescription": "Files updates automatically applied.",
                "commitSetId": 84,
                "commitUser": "admin",
                "configVersion": 39,
                "containsDkimKeys": false,
                "fileSize": 69723751,
                "filename": "MailMarshal-10.0.1-ManualBackup_05-May-2021-05-17-51",
                "info": {
                    "backupTime": 1620217071,
                    "backupTimeStr": "2021-05-05T12:17:51Z",
                    "backupType": "full",
                    "backupUser": "admin",
                    "commitDescription": "Files updates automatically applied.",
                    "commitSetId": 84,
                    "commitUser": "admin",
                    "configVersion": 39,
                    "containsDkimKeys": false,
                    "productVersion": "10.0.1.2030"
                },
                "lastModified": 1620217080,
                "productVersion": "10.0.1.2030"
            },
            {
                "backupTime": 1620198296,
                "backupTimeStr": "2021-05-05T07:04:56Z",
                "backupType": "full",
                "backupUser": "admin",
                "commitDescription": "Committing Marshal RBL credentials update",
                "commitSetId": 83,
                "commitUser": "admin",
                "configVersion": 39,
                "containsDkimKeys": false,
                "fileSize": 69718651,
                "filename": "MailMarshal-10.0.1-ManualBackup_05-May-2021-00-04-56",
                "info": {
                    "backupTime": 1620198296,
                    "backupTimeStr": "2021-05-05T07:04:56Z",
                    "backupType": "full",
                    "backupUser": "admin",
                    "commitDescription": "Committing Marshal RBL credentials update",
                    "commitSetId": 83,
                    "commitUser": "admin",
                    "configVersion": 39,
                    "containsDkimKeys": false,
                    "productVersion": "10.0.1.2030"
                },
                "lastModified": 1620198305,
                "productVersion": "10.0.1.2030"
            },
            {
                "backupTime": 1620198215,
                "backupTimeStr": "2021-05-05T07:03:35Z",
                "backupType": "full",
                "backupUser": "admin",
                "commitDescription": "Committing Marshal RBL credentials update",
                "commitSetId": 82,
                "commitUser": "admin",
                "configVersion": 39,
                "containsDkimKeys": false,
                "fileSize": 69718538,
                "filename": "MailMarshal-10.0.1-ManualBackup_05-May-2021-00-03-35",
                "info": {
                    "backupTime": 1620198215,
                    "backupTimeStr": "2021-05-05T07:03:35Z",
                    "backupType": "full",
                    "backupUser": "admin",
                    "commitDescription": "Committing Marshal RBL credentials update",
                    "commitSetId": 82,
                    "commitUser": "admin",
                    "configVersion": 39,
                    "containsDkimKeys": false,
                    "productVersion": "10.0.1.2030"
                },
                "lastModified": 1620198225,
                "productVersion": "10.0.1.2030"
            },
            {
                "backupTime": 1620169200,
                "backupTimeStr": "2021-05-04T23:00:00Z",
                "backupType": "full",
                "backupUser": "admin",
                "commitDescription": "Files updates automatically applied.",
                "commitSetId": 80,
                "commitUser": "admin",
                "configVersion": 39,
                "containsDkimKeys": false,
                "fileSize": 69718485,
                "filename": "MailMarshal-10.0.1-AutomaticBackup_04-May-2021-16-00-00",
                "info": {
                    "backupTime": 1620169200,
                    "backupTimeStr": "2021-05-04T23:00:00Z",
                    "backupType": "full",
                    "backupUser": "admin",
                    "commitDescription": "Files updates automatically applied.",
                    "commitSetId": 80,
                    "commitUser": "admin",
                    "configVersion": 39,
                    "containsDkimKeys": false,
                    "productVersion": "10.0.1.2030"
                },
                "lastModified": 1620169209,
                "productVersion": "10.0.1.2030"
            },
            {
                "backupTime": 1620111035,
                "backupTimeStr": "2021-05-04T06:50:35Z",
                "backupType": "full",
                "backupUser": "admin",
                "commitDescription": "Committing Marshal RBL credentials update",
                "commitSetId": 79,
                "commitUser": "admin",
                "configVersion": 39,
                "containsDkimKeys": false,
                "fileSize": 69714284,
                "filename": "MailMarshal-10.0.1-ManualBackup_03-May-2021-23-50-35",
                "info": {
                    "backupTime": 1620111035,
                    "backupTimeStr": "2021-05-04T06:50:35Z",
                    "backupType": "full",
                    "backupUser": "admin",
                    "commitDescription": "Committing Marshal RBL credentials update",
                    "commitSetId": 79,
                    "commitUser": "admin",
                    "configVersion": 39,
                    "containsDkimKeys": false,
                    "productVersion": "10.0.1.2030"
                },
                "lastModified": 1620111045,
                "productVersion": "10.0.1.2030"
            },
            {
                "backupTime": 1620082800,
                "backupTimeStr": "2021-05-03T23:00:00Z",
                "backupType": "full",
                "backupUser": "admin",
                "commitDescription": "Files updates automatically applied.",
                "commitSetId": 77,
                "commitUser": "admin",
                "configVersion": 39,
                "containsDkimKeys": false,
                "fileSize": 69714339,
                "filename": "MailMarshal-10.0.1-AutomaticBackup_03-May-2021-16-00-00",
                "info": {
                    "backupTime": 1620082800,
                    "backupTimeStr": "2021-05-03T23:00:00Z",
                    "backupType": "full",
                    "backupUser": "admin",
                    "commitDescription": "Files updates automatically applied.",
                    "commitSetId": 77,
                    "commitUser": "admin",
                    "configVersion": 39,
                    "containsDkimKeys": false,
                    "productVersion": "10.0.1.2030"
                },
                "lastModified": 1620082809,
                "productVersion": "10.0.1.2030"
            }
        ]
    }
}
```

#### Human Readable Output

>### Automatic Configured Backups
>|Filename|Contains Dkim Keys|Backup User|Product Version|Config Version|Commit Description|Backup Type|
>|---|---|---|---|---|---|---|
>| MailMarshal-10.0.1-ManualBackup_10-May-2021-05-40-05 | false | admin | 10.0.1.2030 | 39 | Committing Marshal RBL credentials update | full |
>| MailMarshal-10.0.1-AutomaticBackup_09-May-2021-16-00-00 | false | admin | 10.0.1.2030 | 39 | Files updates automatically applied. | full |
>| MailMarshal-10.0.1-AutomaticBackup_08-May-2021-16-00-00 | false | admin | 10.0.1.2030 | 39 | Files updates automatically applied. | full |
>| MailMarshal-10.0.1-AutomaticBackup_07-May-2021-16-00-00 | false | admin | 10.0.1.2030 | 39 | Files updates automatically applied. | full |
>| MailMarshal-10.0.1-AutomaticBackup_06-May-2021-16-00-00 | false | admin | 10.0.1.2030 | 39 | Files updates automatically applied. | full |
>| MailMarshal-10.0.1-ManualBackup_06-May-2021-04-32-55 | false | admin | 10.0.1.2030 | 39 | Committing Marshal RBL credentials update | full |
>| MailMarshal-10.0.1-ManualBackup_06-May-2021-00-26-20 | false | admin | 10.0.1.2030 | 39 | Committing Marshal RBL credentials update | full |
>| MailMarshal-10.0.1-ManualBackup_06-May-2021-00-20-25 | false | admin | 10.0.1.2030 | 39 | Committing Marshal RBL credentials update | full |
>| MailMarshal-10.0.1-ManualBackup_05-May-2021-23-43-56 | false | admin | 10.0.1.2030 | 39 | Committing Marshal RBL credentials update | full |
>| MailMarshal-10.0.1-ManualBackup_05-May-2021-23-41-20 | false | admin | 10.0.1.2030 | 39 | Committing Marshal RBL credentials update | full |
>| MailMarshal-10.0.1-AutomaticBackup_05-May-2021-16-00-00 | false | admin | 10.0.1.2030 | 39 | Committing Marshal RBL credentials update | full |
>| MailMarshal-10.0.1-ManualBackup_05-May-2021-05-31-09 | false | admin | 10.0.1.2030 | 39 | Committing Marshal RBL credentials update | full |
>| MailMarshal-10.0.1-ManualBackup_05-May-2021-05-28-09 | false | admin | 10.0.1.2030 | 39 | Committing Marshal RBL credentials update | full |
>| MailMarshal-10.0.1-ManualBackup_05-May-2021-05-25-31 | false | admin | 10.0.1.2030 | 39 | Files updates automatically applied. | full |
>| MailMarshal-10.0.1-ManualBackup_05-May-2021-05-21-50 | false | admin | 10.0.1.2030 | 39 | Files updates automatically applied. | full |
>| MailMarshal-10.0.1-ManualBackup_05-May-2021-05-17-51 | false | admin | 10.0.1.2030 | 39 | Files updates automatically applied. | full |
>| MailMarshal-10.0.1-ManualBackup_05-May-2021-00-04-56 | false | admin | 10.0.1.2030 | 39 | Committing Marshal RBL credentials update | full |
>| MailMarshal-10.0.1-ManualBackup_05-May-2021-00-03-35 | false | admin | 10.0.1.2030 | 39 | Committing Marshal RBL credentials update | full |
>| MailMarshal-10.0.1-AutomaticBackup_04-May-2021-16-00-00 | false | admin | 10.0.1.2030 | 39 | Files updates automatically applied. | full |
>| MailMarshal-10.0.1-ManualBackup_03-May-2021-23-50-35 | false | admin | 10.0.1.2030 | 39 | Committing Marshal RBL credentials update | full |
>| MailMarshal-10.0.1-AutomaticBackup_03-May-2021-16-00-00 | false | admin | 10.0.1.2030 | 39 | Files updates automatically applied. | full |


### trustwave-seg-automatic-config-backup-restore
***
Restores a specific automatic configuration backup.


#### Base Command

`trustwave-seg-automatic-config-backup-restore`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the backup to restore (e.g., MailMarshal-10.0.1-ManualBackup_11-Apr-2021-05-00-10). | Required | 
| timeout | The timeout for the request in seconds. This request might take a while. If the request fails due to a connectivity error, try to add more time to this argument. Default is 30. | Optional | 
| include_dkim | Whether DKIM (DomainKeys Identified Mail) should be used. Possible values are: true, false. Default is false. | Optional | 
| dkim_password | If include_dkim is true, the DKIM password for the action. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TrustwaveSEG.AutomaticBackupRestore.errors | String | The errors of the AutomaticBackupRestore. | 
| TrustwaveSEG.AutomaticBackupRestore.reason | String | The reason for the AutomaticBackupRestore. | 
| TrustwaveSEG.AutomaticBackupRestore.warnings | String | The warnings of the AutomaticBackupRestore. | 


#### Command Example
```!trustwave-seg-automatic-config-backup-restore name="MailMarshal-10.0.1-ManualBackup_05-May-2021-05-25-31" timeout=200```

#### Context Example
```json
{
    "TrustwaveSEG": {
        "AutomaticBackupRestore": {
            "errors": "",
            "reason": "backup restored",
            "warnings": "DKIM password not set - DKIM restore is ignored.\n"
        }
    }
}
```

#### Human Readable Output

>### Automatic Configuration Backup Restore Completed
>|Name|Reason|Warnings|
>|---|---|---|
>| MailMarshal-10.0.1-ManualBackup_05-May-2021-05-25-31 | backup restored | DKIM password not set - DKIM restore is ignored.<br/> |


### trustwave-seg-automatic-config-backup-run
***
Run automatic backup now.


#### Base Command

`trustwave-seg-automatic-config-backup-run`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| timeout | The timeout for the request in seconds. This request might take a while. If the request fails due to a connectivity error, try to add more seconds to the timeout. Default is 30. | Optional | 
| include_dkim | Choose if DKIM (DomainKeys Identified Mail) should be used. Possible values are: true, false. Default is false. | Optional | 
| dkim_password | If include_dkim equals true - Please specify the DKIM password (defaults to configured password). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TrustwaveSEG.AutomaticBackupRun.backupName | String | The backup name of the automatic backup run. | 
| TrustwaveSEG.AutomaticBackupRun.reason | String | The reason for the automatic backup run. | 


#### Command Example
```!trustwave-seg-automatic-config-backup-run```

#### Context Example
```json
{
    "TrustwaveSEG": {
        "AutomaticBackupRun": {
            "backupName": "MailMarshal-10.0.1-ManualBackup_10-May-2021-05-50-37",
            "reason": "backup successful"
        }
    }
}
```

#### Human Readable Output

>### Automatic Configuration Backup Run Completed
>|Backup Name|Reason|
>|---|---|
>| MailMarshal-10.0.1-ManualBackup_10-May-2021-05-50-37 | backup successful |


### trustwave-seg-list-alerts
***
Gets a list of current alerts.


#### Base Command

`trustwave-seg-list-alerts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| active_only | Whether to return only active alarms. Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TrustwaveSEG.Alert.active | Boolean | The activity of the alert. | 
| TrustwaveSEG.Alert.description | String | The description of the alert. | 
| TrustwaveSEG.Alert.node | Number | The node of the alert. | 
| TrustwaveSEG.Alert.source | String | The source of the alert. | 
| TrustwaveSEG.Alert.triggered | Number | The trigger of the alert. | 
| TrustwaveSEG.Alert.type | Number | The type of the alert. | 


#### Command Example
```!trustwave-seg-list-alerts```

#### Context Example
```json
{
    "TrustwaveSEG": {
        "Alert": [
            {
                "active": false,
                "description": "MMEngine is now running",
                "node": 1,
                "source": "Engine",
                "triggered": 1618920768,
                "type": 0
            },
            {
                "active": false,
                "description": "MMSender is now running",
                "node": 1,
                "source": "Sender",
                "triggered": 1618920374,
                "type": 0
            },
            {
                "active": false,
                "description": "MMReceiver is now running",
                "node": 1,
                "source": "Receiver",
                "triggered": 1618920374,
                "type": 0
            },
            {
                "active": false,
                "description": "MMEngine has stopped",
                "node": 1,
                "source": "Engine",
                "triggered": 1618918602,
                "type": 7
            },
            {
                "active": false,
                "description": "MMSender has stopped",
                "node": 1,
                "source": "Sender",
                "triggered": 1618918602,
                "type": 7
            },
            {
                "active": false,
                "description": "MMReceiver has stopped",
                "node": 1,
                "source": "Receiver",
                "triggered": 1618918602,
                "type": 7
            }
        ]
    }
}
```

#### Human Readable Output

>### Alerts
>|Description|Active|Node|Source|Triggered|
>|---|---|---|---|---|
>| MMEngine is now running | false | 1 | Engine | 20/04/2021, 12:12:48 |
>| MMSender is now running | false | 1 | Sender | 20/04/2021, 12:06:14 |
>| MMReceiver is now running | false | 1 | Receiver | 20/04/2021, 12:06:14 |
>| MMEngine has stopped | false | 1 | Engine | 20/04/2021, 11:36:42 |
>| MMSender has stopped | false | 1 | Sender | 20/04/2021, 11:36:42 |
>| MMReceiver has stopped | false | 1 | Receiver | 20/04/2021, 11:36:42 |


### trustwave-seg-statistics
***
Gets Trustwave SEG statistics. Must provide a start time or time range.


#### Base Command

`trustwave-seg-statistics`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| time_range | An optional time range, i.e., 3 months, 1 week, 1 day ago, etc. | Optional | 
| start_time | Start time in the format of: YYYY-mm-ddTHH:MM:SSZ or i.e., 3 months, 1 week, 1 day ago, etc. Given only the start_time, end_time will be set to the current time. | Optional | 
| end_time | End time in the format of: YYYY-mm-ddTHH:MM:SSZ or i.e., 3 months, 1 week, 1 day ago, etc. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TrustwaveSEG.Statistics.maliciousUrls | Number | The number of malicious URLs in the statistics. | 
| TrustwaveSEG.Statistics.msgsBlendedThreats | Number | The number blended threats messages in the statistics. | 
| TrustwaveSEG.Statistics.msgsIn | Number | The number of incoming messages in the statistics. | 
| TrustwaveSEG.Statistics.msgsInternal | Number | The number of internal messages in the statistics. | 
| TrustwaveSEG.Statistics.msgsOut | Number | The number of outgoing messages in the statistics. | 
| TrustwaveSEG.Statistics.msgsSpam | Number | The number of spam messages in the statistics. | 
| TrustwaveSEG.Statistics.msgsVirus | Number | The number of virus messages in the statistics. | 
| TrustwaveSEG.Statistics.numQuarantined | Number | The number of quarantined messages in the statistics. | 
| TrustwaveSEG.Statistics.numQuarantinesPerMsg | Number | The number of quarantines per message in the statistics. | 
| TrustwaveSEG.Statistics.pFolders | Number | The number of pFolders in the statistics. | 
| TrustwaveSEG.Statistics.pThreats | Number | The number of pThreats in the statistics. | 
| TrustwaveSEG.Statistics.safeClicks | Number | The number of safe clicks in the statistics.in the statistics. | 
| TrustwaveSEG.Statistics.unsafeClicks | Number | The number of unsafe clicks | 
| TrustwaveSEG.Statistics.unsafeUrls | Number | The number of unsafe URLs in the statistics. | 
| TrustwaveSEG.Statistics.urlsFound | Number | The number of URLs found in the statistics. | 
| TrustwaveSEG.Statistics.urlsRewritten | Number | The number of urls rewritten in the statistics. | 
| TrustwaveSEG.Statistics.virusDetected | Number | The number of viruses detected in the statistics. | 
| TrustwaveSEG.Statistics.virusScanned | Number | The number of virus-scanned statistics. | 


#### Command Example
```!trustwave-seg-statistics time_range="1 day ago"```

#### Context Example
```json
{
    "TrustwaveSEG": {
        "Statistics": {
            "maliciousUrls": 0,
            "msgsBlendedThreats": 0,
            "msgsIn": 0,
            "msgsInternal": 0,
            "msgsOut": 0,
            "msgsSpam": 0,
            "msgsVirus": 0,
            "numQuarantined": 0,
            "numQuarantinesPerMsg": 0,
            "pFolders": null,
            "pThreats": null,
            "safeClicks": 0,
            "unsafeClicks": 0,
            "unsafeUrls": 0,
            "urlsFound": 0,
            "urlsRewritten": 0,
            "virusDetected": 0,
            "virusScanned": 0
        }
    }
}
```

#### Human Readable Output

>### Statistics Information between 09/05/2021, 12:50:34 to 10/05/2021, 12:50:34
>|Msgs In|Msgs Out|Malicious Urls|Msgs Blended Threats|Msgs Spam|Msgs Virus|Num Quarantined|Unsafe Clicks|Unsafe Urls|Virus Detected|
>|---|---|---|---|---|---|---|---|---|---|
>| 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |


### trustwave-seg-list-servers
***
Gets a list of servers.


#### Base Command

`trustwave-seg-list-servers`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TrustwaveSEG.Server.configCommitSetId | Number | The configuration commit set ID of the server. | 
| TrustwaveSEG.Server.configTimeStamp | Number | The configuration timestamp of the server. | 
| TrustwaveSEG.Server.disconnectedReason | String | Disconnected reason for the server. | 
| TrustwaveSEG.Server.isActive | Boolean | Activation status of the Server. | 
| TrustwaveSEG.Server.isConfigDeferred | Boolean | Whether the configuration of the server is deferred. | 
| TrustwaveSEG.Server.lastConnected | Number | Last connected time of the server. | 
| TrustwaveSEG.Server.osVersion | String | The operating system version of the server. | 
| TrustwaveSEG.Server.pServiceStatus.description | String | The description of the server. | 
| TrustwaveSEG.Server.pServiceStatus.lastError | Unknown | Last error of the server. | 
| TrustwaveSEG.Server.pServiceStatus.name | String | The name of the server. | 
| TrustwaveSEG.Server.pServiceStatus.serviceId | Number | The service ID of the server. | 
| TrustwaveSEG.Server.pServiceStatus.state | Number | The state of the server. | 
| TrustwaveSEG.Server.productVersion | String | The product version of the server. | 
| TrustwaveSEG.Server.serverDescription | String | The description of the server. | 
| TrustwaveSEG.Server.serverId | Number | The ID of the server. | 
| TrustwaveSEG.Server.serverLocation | String | The location of the server. | 
| TrustwaveSEG.Server.serverName | String | The name of the server. | 
| TrustwaveSEG.Server.timeZoneName | String | Timezone name of the server. | 
| TrustwaveSEG.Server.timeZoneOffset | Number | Timezone offset of the server. | 


#### Command Example
```!trustwave-seg-list-servers```

#### Context Example
```json
{
    "TrustwaveSEG": {
        "Server": {
            "configCommitSetId": 102,
            "configTimeStamp": 0,
            "disconnectedReason": "RPC call timed-out",
            "isActive": true,
            "isConfigDeferred": false,
            "lastConnected": 1620650994,
            "osVersion": "Windows Server 2016 ",
            "pServiceStatus": [
                {
                    "description": "Trustwave SEG Receiver.\nAccepts email messages for processing.",
                    "lastError": null,
                    "name": "Receiver",
                    "serviceId": 0,
                    "state": 0
                },
                {
                    "description": "Trustwave SEG Content Engine.\nApplies your email policy to messages.",
                    "lastError": null,
                    "name": "Engine",
                    "serviceId": 1,
                    "state": 0
                },
                {
                    "description": "Trustwave SEG Sender.\nForwards processed messages for delivery.",
                    "lastError": null,
                    "name": "Sender",
                    "serviceId": 2,
                    "state": 0
                }
            ],
            "productVersion": "10.0.1.2030",
            "serverDescription": "",
            "serverId": 1,
            "serverLocation": "test",
            "serverName": "DEV-TRUSTWAVE",
            "timeZoneName": "Jerusalem Daylight Time",
            "timeZoneOffset": -120
        }
    }
}
```

#### Human Readable Output

>### Servers Details
>|Server Name|Server Id|Product Version|Is Active|Server Location|Services|
>|---|---|---|---|---|---|
>| DEV-TRUSTWAVE | 1 | 10.0.1.2030 | true | test | Receiver, Engine, Sender |


### trustwave-seg-get-server
***
Gets server details.


#### Base Command

`trustwave-seg-get-server`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| server_id | The ID of the server from which to retrieve information. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TrustwaveSEG.Server.configCommitSetId | Number | The configuration commit set ID of the server. | 
| TrustwaveSEG.Server.configTimeStamp | Number | The configuration timestamp of the server. | 
| TrustwaveSEG.Server.disconnectedReason | String | Disconnected reason for the server. | 
| TrustwaveSEG.Server.isActive | Boolean | Activation status of the Server. | 
| TrustwaveSEG.Server.isConfigDeferred | Boolean | Whether the configuration of the server is deferred. | 
| TrustwaveSEG.Server.lastConnected | Number | Last connected time of the server. | 
| TrustwaveSEG.Server.osVersion | String | The operating system version of the server. | 
| TrustwaveSEG.Server.pServiceStatus.description | String | The description of the server. | 
| TrustwaveSEG.Server.pServiceStatus.lastError | Unknown | Last error of the server. | 
| TrustwaveSEG.Server.pServiceStatus.name | String | The name of the server. | 
| TrustwaveSEG.Server.pServiceStatus.serviceId | Number | The service ID of the server. | 
| TrustwaveSEG.Server.pServiceStatus.state | Number | The state of the server. | 
| TrustwaveSEG.Server.productVersion | String | The product version of the server. | 
| TrustwaveSEG.Server.serverDescription | String | The description of the server. | 
| TrustwaveSEG.Server.serverId | Number | The ID of the server. | 
| TrustwaveSEG.Server.serverLocation | String | The location of the server. | 
| TrustwaveSEG.Server.serverName | String | The name of the server. | 
| TrustwaveSEG.Server.timeZoneName | String | Timezone name of the server. | 
| TrustwaveSEG.Server.timeZoneOffset | Number | Timezone offset of the server. | 


#### Command Example
```!trustwave-seg-get-server server_id="1"```

#### Context Example
```json
{
    "TrustwaveSEG": {
        "Server": {
            "configCommitSetId": 102,
            "configTimeStamp": 0,
            "disconnectedReason": "RPC call timed-out",
            "isActive": false,
            "isConfigDeferred": false,
            "lastConnected": 1620650994,
            "osVersion": "Windows Server 2016 ",
            "pServiceStatus": [
                {
                    "description": "Trustwave SEG Receiver.\nAccepts email messages for processing.",
                    "lastError": null,
                    "name": "Receiver",
                    "serviceId": 0,
                    "state": 0
                },
                {
                    "description": "Trustwave SEG Content Engine.\nApplies your email policy to messages.",
                    "lastError": null,
                    "name": "Engine",
                    "serviceId": 1,
                    "state": 0
                },
                {
                    "description": "Trustwave SEG Sender.\nForwards processed messages for delivery.",
                    "lastError": null,
                    "name": "Sender",
                    "serviceId": 2,
                    "state": 0
                }
            ],
            "productVersion": "10.0.1.2030",
            "serverDescription": "",
            "serverId": 1,
            "serverLocation": "test",
            "serverName": "DEV-TRUSTWAVE",
            "timeZoneName": "Jerusalem Daylight Time",
            "timeZoneOffset": -120
        }
    }
}
```

#### Human Readable Output

>### Server Details. ID: 1
>|Server Name|Server Id|Product Version|Is Active|Server Location|Services|
>|---|---|---|---|---|---|
>| DEV-TRUSTWAVE | 1 | 10.0.1.2030 | false | test | Receiver, Engine, Sender |


### trustwave-seg-list-classifications
***
Gets a list of classifications.


#### Base Command

`trustwave-seg-list-classifications`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TrustwaveSEG.Classification.code | Number | The code of the classification. | 
| TrustwaveSEG.Classification.id | Number | The ID of the classification. | 
| TrustwaveSEG.Classification.name | String | The name of the classification. | 
| TrustwaveSEG.Classification.type | Number | The type of the classification. | 


#### Command Example
```!trustwave-seg-list-classifications```

#### Context Example
```json
{
    "TrustwaveSEG": {
        "Classification": [
            {
                "code": 1,
                "id": 1,
                "name": "Folders",
                "type": 1
            },
            {
                "code": 2,
                "id": 2,
                "name": "Mail Recycle Bin",
                "type": 1
            },
            {
                "code": 3,
                "id": 3,
                "name": "Dead Letters",
                "type": 1
            },
            {
                "code": 4,
                "id": 4,
                "name": "Unpacking",
                "type": 1
            },
            {
                "code": 5,
                "id": 5,
                "name": "Routing",
                "type": 1
            },
            {
                "code": 7,
                "id": 6,
                "name": "Undetermined",
                "type": 1
            },
            {
                "code": 8,
                "id": 7,
                "name": "Malformed",
                "type": 1
            },
            {
                "code": 9,
                "id": 8,
                "name": "Virus",
                "type": 1
            },
            {
                "code": 10,
                "id": 9,
                "name": "Spam",
                "type": 1
            },
            {
                "code": 11,
                "id": 10,
                "name": "Archiving",
                "type": 1
            },
            {
                "code": 1,
                "id": 11,
                "name": "Delivered successfully",
                "type": 0
            },
            {
                "code": 2,
                "id": 12,
                "name": "Temporarily undeliverable",
                "type": 0
            },
            {
                "code": 3,
                "id": 13,
                "name": "Undeliverable",
                "type": 0
            },
            {
                "code": 4,
                "id": 14,
                "name": "Message killed",
                "type": 0
            },
            {
                "code": 5,
                "id": 15,
                "name": "Delivery not tried",
                "type": 0
            },
            {
                "code": 6,
                "id": 16,
                "name": "Delivered successfully over TLS",
                "type": 0
            },
            {
                "code": 7,
                "id": 17,
                "name": "Temporarily undeliverable due to TLS",
                "type": 0
            },
            {
                "code": 1,
                "id": 18,
                "name": "Operator passthrough",
                "type": 3
            },
            {
                "code": 2,
                "id": 19,
                "name": "Operator deleted",
                "type": 3
            },
            {
                "code": 3,
                "id": 20,
                "name": "Operator forwarded",
                "type": 3
            },
            {
                "code": 4,
                "id": 21,
                "name": "Operator reprocessed",
                "type": 3
            },
            {
                "code": 5,
                "id": 22,
                "name": "Operator continued",
                "type": 3
            },
            {
                "code": 6,
                "id": 23,
                "name": "Operator sent to recycle bin",
                "type": 3
            },
            {
                "code": 7,
                "id": 24,
                "name": "Operator restored from recycle bin",
                "type": 3
            },
            {
                "code": 8,
                "id": 25,
                "name": "Operator emptied recycle bin",
                "type": 3
            },
            {
                "code": 9,
                "id": 26,
                "name": "User deleted",
                "type": 3
            },
            {
                "code": 10,
                "id": 27,
                "name": "Forwarded to Trustwave as spam",
                "type": 3
            },
            {
                "code": 11,
                "id": 28,
                "name": "Forwarded to Trustwave as not spam",
                "type": 3
            },
            {
                "code": 12,
                "id": 29,
                "name": "Message viewed in console",
                "type": 3
            },
            {
                "code": 1,
                "id": 30,
                "name": "Deleted by rules",
                "type": 4
            },
            {
                "code": 1000,
                "id": 31,
                "name": "Sent History",
                "type": 1
            },
            {
                "code": 1001,
                "id": 32,
                "name": "DMARC Reports",
                "type": 1
            },
            {
                "code": 1002,
                "id": 33,
                "name": "BEC - Executive Name",
                "type": 1
            },
            {
                "code": 1003,
                "id": 34,
                "name": "Suspect",
                "type": 1
            },
            {
                "code": 1004,
                "id": 35,
                "name": "Spoofed",
                "type": 1
            },
            {
                "code": 1005,
                "id": 36,
                "name": "Junk",
                "type": 1
            },
            {
                "code": 1006,
                "id": 37,
                "name": "Archive In",
                "type": 1
            },
            {
                "code": 1007,
                "id": 38,
                "name": "Archive Out",
                "type": 1
            },
            {
                "code": 1008,
                "id": 39,
                "name": "Language",
                "type": 1
            },
            {
                "code": 1009,
                "id": 40,
                "name": "Parked Large Files",
                "type": 1
            },
            {
                "code": 1010,
                "id": 41,
                "name": "Oversize",
                "type": 1
            },
            {
                "code": 1011,
                "id": 42,
                "name": "Awaiting Challenge - Response",
                "type": 1
            },
            {
                "code": 1012,
                "id": 43,
                "name": "Attachment Type - Executables",
                "type": 1
            },
            {
                "code": 1013,
                "id": 44,
                "name": "Attachment Type - Images",
                "type": 1
            },
            {
                "code": 1014,
                "id": 45,
                "name": "Attachment Type - Video and Sound",
                "type": 1
            },
            {
                "code": 1015,
                "id": 46,
                "name": "Attachment Type - Encrypted",
                "type": 1
            },
            {
                "code": 1016,
                "id": 47,
                "name": "Attachment Type - Unknown",
                "type": 1
            },
            {
                "code": 1017,
                "id": 48,
                "name": "Policy Breaches",
                "type": 1
            },
            {
                "code": 1018,
                "id": 49,
                "name": "Policy Breaches - SEC",
                "type": 1
            },
            {
                "code": 1019,
                "id": 50,
                "name": "Policy Breaches - SOX",
                "type": 1
            },
            {
                "code": 1020,
                "id": 51,
                "name": "Attachment Type - Documents",
                "type": 1
            },
            {
                "code": 1021,
                "id": 52,
                "name": "Suspect Images",
                "type": 1
            },
            {
                "code": 1022,
                "id": 53,
                "name": "Policy Breaches - HIPAA",
                "type": 1
            },
            {
                "code": 1023,
                "id": 54,
                "name": "Spam - Confirmed",
                "type": 1
            },
            {
                "code": 1024,
                "id": 55,
                "name": "Spam - Scams",
                "type": 1
            },
            {
                "code": 1025,
                "id": 56,
                "name": "Spam - Suspected",
                "type": 1
            },
            {
                "code": 1026,
                "id": 57,
                "name": "TLS Failures",
                "type": 1
            },
            {
                "code": 1027,
                "id": 58,
                "name": "DKIM Failures",
                "type": 1
            },
            {
                "code": 1028,
                "id": 59,
                "name": "DKIM Signing Failures",
                "type": 1
            },
            {
                "code": 1029,
                "id": 60,
                "name": "Malware",
                "type": 1
            },
            {
                "code": 1030,
                "id": 61,
                "name": "Malware - Virus Scanner Errors",
                "type": 1
            },
            {
                "code": 1031,
                "id": 62,
                "name": "Malware - Suspected",
                "type": 1
            },
            {
                "code": 1032,
                "id": 63,
                "name": "SenderID Failures",
                "type": 1
            },
            {
                "code": 1033,
                "id": 64,
                "name": "Suspect URLs",
                "type": 1
            },
            {
                "code": 1034,
                "id": 65,
                "name": "Malware - AMAX",
                "type": 1
            },
            {
                "code": 1035,
                "id": 66,
                "name": "Malformed PDF",
                "type": 1
            },
            {
                "code": 1036,
                "id": 67,
                "name": "DMARC Failures - Quarantine policy",
                "type": 1
            },
            {
                "code": 1037,
                "id": 68,
                "name": "DMARC Failures - Reject policy",
                "type": 1
            },
            {
                "code": 1038,
                "id": 69,
                "name": "BEC - Fraud Filter",
                "type": 1
            },
            {
                "code": 1039,
                "id": 70,
                "name": "BEC - Domain Similarity",
                "type": 1
            },
            {
                "code": 71,
                "id": 71,
                "name": "Product Info Request",
                "type": 2
            },
            {
                "code": 73,
                "id": 72,
                "name": "Contains a CV",
                "type": 2
            },
            {
                "code": 74,
                "id": 73,
                "name": "Has Multiple Recipients",
                "type": 2
            },
            {
                "code": 75,
                "id": 74,
                "name": "Message to Old Domain",
                "type": 2
            },
            {
                "code": 72,
                "id": 75,
                "name": "Release Requests",
                "type": 2
            }
        ]
    }
}
```

#### Human Readable Output

>### Classifications
>|Id|Name|
>|---|---|
>| 1 | Folders |
>| 2 | Mail Recycle Bin |
>| 3 | Dead Letters |
>| 4 | Unpacking |
>| 5 | Routing |
>| 6 | Undetermined |
>| 7 | Malformed |
>| 8 | Virus |
>| 9 | Spam |
>| 10 | Archiving |
>| 11 | Delivered successfully |
>| 12 | Temporarily undeliverable |
>| 13 | Undeliverable |
>| 14 | Message killed |
>| 15 | Delivery not tried |
>| 16 | Delivered successfully over TLS |
>| 17 | Temporarily undeliverable due to TLS |
>| 18 | Operator passthrough |
>| 19 | Operator deleted |
>| 20 | Operator forwarded |
>| 21 | Operator reprocessed |
>| 22 | Operator continued |
>| 23 | Operator sent to recycle bin |
>| 24 | Operator restored from recycle bin |
>| 25 | Operator emptied recycle bin |
>| 26 | User deleted |
>| 27 | Forwarded to Trustwave as spam |
>| 28 | Forwarded to Trustwave as not spam |
>| 29 | Message viewed in console |
>| 30 | Deleted by rules |
>| 31 | Sent History |
>| 32 | DMARC Reports |
>| 33 | BEC - Executive Name |
>| 34 | Suspect |
>| 35 | Spoofed |
>| 36 | Junk |
>| 37 | Archive In |
>| 38 | Archive Out |
>| 39 | Language |
>| 40 | Parked Large Files |
>| 41 | Oversize |
>| 42 | Awaiting Challenge - Response |
>| 43 | Attachment Type - Executables |
>| 44 | Attachment Type - Images |
>| 45 | Attachment Type - Video and Sound |
>| 46 | Attachment Type - Encrypted |
>| 47 | Attachment Type - Unknown |
>| 48 | Policy Breaches |
>| 49 | Policy Breaches - SEC |
>| 50 | Policy Breaches - SOX |
>| 51 | Attachment Type - Documents |
>| 52 | Suspect Images |
>| 53 | Policy Breaches - HIPAA |
>| 54 | Spam - Confirmed |
>| 55 | Spam - Scams |
>| 56 | Spam - Suspected |
>| 57 | TLS Failures |
>| 58 | DKIM Failures |
>| 59 | DKIM Signing Failures |
>| 60 | Malware |
>| 61 | Malware - Virus Scanner Errors |
>| 62 | Malware - Suspected |
>| 63 | SenderID Failures |
>| 64 | Suspect URLs |
>| 65 | Malware - AMAX |
>| 66 | Malformed PDF |
>| 67 | DMARC Failures - Quarantine policy |
>| 68 | DMARC Failures - Reject policy |
>| 69 | BEC - Fraud Filter |
>| 70 | BEC - Domain Similarity |
>| 71 | Product Info Request |
>| 72 | Contains a CV |
>| 73 | Has Multiple Recipients |
>| 74 | Message to Old Domain |
>| 75 | Release Requests |


### trustwave-seg-list-quarantine-folders
***
Gets a list of folders.


#### Base Command

`trustwave-seg-list-quarantine-folders`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TrustwaveSEG.Folder.description | String | The description of the folder. | 
| TrustwaveSEG.Folder.folderId | Number | The ID of the folder. | 
| TrustwaveSEG.Folder.folderType | Number | The type of the folder. | 
| TrustwaveSEG.Folder.iconIndex | Number | The icon index of the folder. | 
| TrustwaveSEG.Folder.isDeleted | Boolean | Whether the folder is deleted. | 
| TrustwaveSEG.Folder.isFingerprintingEnabled | Boolean | Whether fingerprinting is enabled for the folder. | 
| TrustwaveSEG.Folder.isPassThru | Boolean | Whether pass thru is enabled for the folder. | 
| TrustwaveSEG.Folder.isPublishedInbound | Boolean | Whether the folder is published inbound. | 
| TrustwaveSEG.Folder.isPublishedOutbound | Boolean | Whether the folder is published outbound. | 
| TrustwaveSEG.Folder.isReadOnly | Boolean | Whether the folder is read-only. | 
| TrustwaveSEG.Folder.name | String | The name of the folder. | 
| TrustwaveSEG.Folder.numFiles | Number | The number of files in the folder. | 
| TrustwaveSEG.Folder.parentId | Number | The parent ID of the folder. | 
| TrustwaveSEG.Folder.path | String | The path of the folder. | 
| TrustwaveSEG.Folder.retention | Number | The retention of the folder. | 
| TrustwaveSEG.Folder.securityDescription | String | The security description of the folder. | 


#### Command Example
```!trustwave-seg-list-quarantine-folders```

#### Context Example
```json
{
    "TrustwaveSEG": {
        "Folder": [
            {
                "description": "",
                "folderId": 1,
                "folderType": 4,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Folders",
                "numFiles": 5,
                "parentId": 0,
                "path": "",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "description": "",
                "folderId": 2,
                "folderType": 3,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Mail Recycle Bin",
                "numFiles": 0,
                "parentId": 1,
                "path": "",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "description": "",
                "folderId": 3,
                "folderType": 4,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Dead Letters",
                "numFiles": 0,
                "parentId": 1,
                "path": "DeadLetter",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "description": "Contains messages that could not be processed due to file corruption or other problems with structure.",
                "folderId": 4,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Unpacking",
                "numFiles": 0,
                "parentId": 3,
                "path": "Unpacking",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "description": "Contains messages that could not be delivered due to a DNS lookup problem or other issues.",
                "folderId": 5,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Routing",
                "numFiles": 0,
                "parentId": 3,
                "path": "Routing",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "description": "Contains messages that returned an unexpected result from virus scanning or an external command.",
                "folderId": 7,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Undetermined",
                "numFiles": 0,
                "parentId": 3,
                "path": "Undetermined",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "description": "Contains messages that were blocked or could not be processed due to problems with encoding.",
                "folderId": 8,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Malformed",
                "numFiles": 0,
                "parentId": 3,
                "path": "Malformed",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "description": "Contains messages that could not be fully unpacked but are classified as containing a virus.",
                "folderId": 9,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Virus",
                "numFiles": 0,
                "parentId": 3,
                "path": "Virus",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "description": "Contains messages that could not be fully unpacked but are classified as spam.",
                "folderId": 10,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Spam",
                "numFiles": 0,
                "parentId": 3,
                "path": "Spam",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "description": "Contains messages that could not be delivered to the Archive.",
                "folderId": 11,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Archiving",
                "numFiles": 0,
                "parentId": 3,
                "path": "Archiving",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "description": "Contains historic logs for delivered email.",
                "folderId": 1000,
                "folderType": 5,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": true,
                "name": "Sent History",
                "numFiles": 0,
                "parentId": 1,
                "path": "4B7E81EE-9D7B-46E2-B027-ECDDFD26E947",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "description": "An archive folder for inbound messages with attached DMARC Reports for the local domains.",
                "folderId": 1001,
                "folderType": 6,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": true,
                "name": "DMARC Reports",
                "numFiles": 0,
                "parentId": 1,
                "path": "736A0F9F-A865-4519-A111-DA8A967D45A1",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "description": "Contains messages that match an Executive Name in the From: field.",
                "folderId": 1002,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "BEC - Executive Name",
                "numFiles": 0,
                "parentId": 1,
                "path": "157803C1-1B20-4415-A92F-FA9D871B768C",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "description": "Contains messages with attachments deemed suspect, such as undesirable file extensions.",
                "folderId": 1003,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Suspect",
                "numFiles": 0,
                "parentId": 1,
                "path": "ED86938B-A2C4-4260-A4AB-D80BF8CE9C72",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "description": "Contains messages that are identified as spoofed by the blocked spoofed messages rule.",
                "folderId": 1004,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Spoofed",
                "numFiles": 0,
                "parentId": 1,
                "path": "1AE86AF4-44FC-411D-95E5-20B8F3D0D55E",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "description": "Generic folder for unwanted messages such as chain letters and hoaxes.",
                "folderId": 1005,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Junk",
                "numFiles": 0,
                "parentId": 1,
                "path": "2A3E6EFE-38D6-438D-84B0-BE4AB2B7EFAD",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "description": "An archive folder for all inbound messages.  By default, messages are kept for 3 months.",
                "folderId": 1006,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": true,
                "name": "Archive In",
                "numFiles": 3,
                "parentId": 1,
                "path": "AA55C8DA-7BE2-4EA4-AD99-BAB37FC598DC",
                "retention": 0,
                "securityDescription": ""
            },
            {
                "description": "An archive folder for all outbound messages.  By default, messages are kept for 3 months.",
                "folderId": 1007,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": true,
                "name": "Archive Out",
                "numFiles": 2,
                "parentId": 1,
                "path": "A11F07EA-7569-4596-9BC5-B4A25D428BAE",
                "retention": 93,
                "securityDescription": ""
            },
            {
                "description": "Contains messages blocked because they contain profanity.",
                "folderId": 1008,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Language",
                "numFiles": 0,
                "parentId": 1,
                "path": "6F1422E1-CDB6-4669-ACC7-794CC0669663",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "description": "Used for temporarily 'parking' large outbound messages or message mailouts until after business hours.",
                "folderId": 1009,
                "folderType": 2,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Parked Large Files",
                "numFiles": 0,
                "parentId": 1,
                "path": "350EC7AE-54FF-4106-903C-79871A72E6BC",
                "retention": 0,
                "securityDescription": ""
            },
            {
                "description": "Used for quarantining large messages that exceed a threshold.",
                "folderId": 1010,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Oversize",
                "numFiles": 0,
                "parentId": 1,
                "path": "821EF706-6C63-4F56-8E4C-2E5D18F4FAFA",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "description": "A folder that holds messages awaiting a response in order to be released.",
                "folderId": 1011,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Awaiting Challenge - Response",
                "numFiles": 0,
                "parentId": 1,
                "path": "E6C18E25-6C63-4740-8783-39A8E9818844",
                "retention": 3,
                "securityDescription": ""
            },
            {
                "description": "Contains messages with identified executable attachments.",
                "folderId": 1012,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Attachment Type - Executables",
                "numFiles": 0,
                "parentId": 1,
                "path": "874AE4BA-F735-4067-AC91-DC3453AFC685",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "description": "Used for messages that contain an attached image.",
                "folderId": 1013,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Attachment Type - Images",
                "numFiles": 0,
                "parentId": 1,
                "path": "C004A276-EAEB-4251-ADEC-494FAF0CB713",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "description": "Contains messages with sound or video attachments, such as MP3 or AVI files.",
                "folderId": 1014,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Attachment Type - Video and Sound",
                "numFiles": 0,
                "parentId": 1,
                "path": "B0CD505E-8A44-434B-8194-E65976CDB4D9",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "description": "Used for messages with encrypted attachments, such as encrypted archive files.",
                "folderId": 1015,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Attachment Type - Encrypted",
                "numFiles": 0,
                "parentId": 1,
                "path": "298D738E-7577-4A91-9E6F-03ED0C817F16",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "description": "Contains messages with binary files of an unknown type.",
                "folderId": 1016,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Attachment Type - Unknown",
                "numFiles": 0,
                "parentId": 1,
                "path": "9A978764-CC8C-46F3-892A-D9E663246046",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "description": "Generic folder for messages that breach company policy.",
                "folderId": 1017,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Policy Breaches",
                "numFiles": 0,
                "parentId": 1,
                "path": "5FD9C657-C416-410B-8FA3-EB2BB2709DDE",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "description": "Contains messages which may indicate possible SEC compliance issues.",
                "folderId": 1018,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Policy Breaches - SEC",
                "numFiles": 0,
                "parentId": 1,
                "path": "290D7E3C-79EF-4E9C-8F2F-DCCBF41A2C9D",
                "retention": 365,
                "securityDescription": ""
            },
            {
                "description": "Contains messages which trigger keywords which may indicate possible Sarbanes-Oxley compliance issues.",
                "folderId": 1019,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Policy Breaches - SOX",
                "numFiles": 0,
                "parentId": 1,
                "path": "8DD88244-BBA9-4100-9F54-62C37C4C3C64",
                "retention": 365,
                "securityDescription": ""
            },
            {
                "description": "Contains messages with document attachments, such as PDF files.",
                "folderId": 1020,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Attachment Type - Documents",
                "numFiles": 0,
                "parentId": 1,
                "path": "FECF5729-15B7-4530-BC15-2D22C98EB9A6",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "description": "Used by the integrated Image Analyzer component to hold images that may be Pornographic.",
                "folderId": 1021,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Suspect Images",
                "numFiles": 0,
                "parentId": 1,
                "path": "0E59FDA1-F197-4072-A8BC-3EF514E2E682",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "description": "Contains messages that trigger health-related keywords which may indicate possible HIPAA compliance issues.",
                "folderId": 1022,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Policy Breaches - HIPAA",
                "numFiles": 0,
                "parentId": 1,
                "path": "D3062553-A54C-48DC-9447-372EE2268CB6",
                "retention": 365,
                "securityDescription": ""
            },
            {
                "description": "Used where there is a high degree of confidence that the messages are spam.  The folder is not end-user managed.",
                "folderId": 1023,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Spam - Confirmed",
                "numFiles": 0,
                "parentId": 1,
                "path": "3EFF33E4-22C3-41EA-98D7-74E3BB6357FD",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "description": "Suspected 419, Lottery and other scam emails.",
                "folderId": 1024,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Spam - Scams",
                "numFiles": 0,
                "parentId": 1,
                "path": "C95F143E-B4CD-4A10-9E3D-6E096CD19908",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "description": "Used where the message is suspected as spam.  The folder is  end-user managed.",
                "folderId": 1025,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": true,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Spam - Suspected",
                "numFiles": 0,
                "parentId": 1,
                "path": "335E332D-57D4-4D3A-BE50-C620E9D63151",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "description": "Contains messages that failed to meet TLS criteria.",
                "folderId": 1026,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "TLS Failures",
                "numFiles": 0,
                "parentId": 1,
                "path": "192C2502-065C-48B6-BF0C-091C09CA9131",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "description": "Contains messages that failed to pass DKIM verification.",
                "folderId": 1027,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "DKIM Failures",
                "numFiles": 0,
                "parentId": 1,
                "path": "1AE86AF4-44FC-411D-95E5-20B8F3D0D55E",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "description": "Contains messages that could not have a DKIM signature applied.",
                "folderId": 1028,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "DKIM Signing Failures",
                "numFiles": 0,
                "parentId": 1,
                "path": "1F1EFD91-6E75-4DE8-B277-13C4997BE17F",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "description": "Messages tagged as having malware by an anti-virus scanner.",
                "folderId": 1029,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Malware",
                "numFiles": 0,
                "parentId": 1,
                "path": "C9A5C59E-AA24-472B-9B39-A374354F0D05",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "description": "Messages that have caused the anti-virus scanner to report an error.",
                "folderId": 1030,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Malware - Virus Scanner Errors",
                "numFiles": 0,
                "parentId": 1,
                "path": "23AFE871-65F2-4C91-B02B-942C96AB73AB",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "description": "Messages suspected of having malicious content by one of the gateway's threat filters.",
                "folderId": 1031,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Malware - Suspected",
                "numFiles": 0,
                "parentId": 1,
                "path": "C0FE5CD3-71EF-4A94-B36D-CA319D674A5D",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "description": "Contains messages that failed to pass SenderID verification.",
                "folderId": 1032,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "SenderID Failures",
                "numFiles": 0,
                "parentId": 1,
                "path": "C5510AFE-7119-4138-BD8D-5240BB3A94C4",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "description": "Contains messages that include suspect URLs.",
                "folderId": 1033,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Suspect URLs",
                "numFiles": 0,
                "parentId": 1,
                "path": "CE15B1F6-0839-4A61-AD0C-D87E625CB14F",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "description": "Contains messages suspected of having malicious content by the Advanced Malware and Exploit Detection (AMAX) filter.",
                "folderId": 1034,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Malware - AMAX",
                "numFiles": 0,
                "parentId": 1,
                "path": "61075A40-337E-4D4C-9368-48822F579AB8",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "description": "Contains messages with PDF attachments that are malformed or corrupt.",
                "folderId": 1035,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Malformed PDF",
                "numFiles": 0,
                "parentId": 1,
                "path": "61075A40-337E-4D4C-9368-48822F579AB8",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "description": "Contains messages that failed to pass DMARC verification, where the DMARC policy for message disposition was \"quarantine\".",
                "folderId": 1036,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "DMARC Failures - Quarantine policy",
                "numFiles": 0,
                "parentId": 1,
                "path": "F6C95742-0EDA-4BE7-9B5D-EE8AA32DBA43",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "description": "Contains messages that failed to pass DMARC verification, where the DMARC policy for message disposition was \"reject\".",
                "folderId": 1037,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "DMARC Failures - Reject policy",
                "numFiles": 0,
                "parentId": 1,
                "path": "51556EA9-390F-4AC2-B521-38B68BC7F3C9",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "description": "Contains messages detected by the BEC Fraud Filter.",
                "folderId": 1038,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "BEC - Fraud Filter",
                "numFiles": 0,
                "parentId": 1,
                "path": "13B5A560-257E-4D2C-8665-DE7840D26F2F",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "description": "Contains messages where the From: domain is similar  to a local domain.",
                "folderId": 1039,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "BEC - Domain Similarity",
                "numFiles": 0,
                "parentId": 1,
                "path": "BE9625E3-2E9A-44A6-8BB4-A4254DFB341F",
                "retention": 7,
                "securityDescription": ""
            }
        ]
    }
}
```

#### Human Readable Output

>### Quarantine Folders
>|Folder Id|Name|Description|Is Deleted|Is Read Only|Num Files|Retention|
>|---|---|---|---|---|---|---|
>| 1 | Folders |  | false | false | 5 | 7 |
>| 2 | Mail Recycle Bin |  | false | false | 0 | 7 |
>| 3 | Dead Letters |  | false | false | 0 | 7 |
>| 4 | Unpacking | Contains messages that could not be processed due to file corruption or other problems with structure. | false | false | 0 | 7 |
>| 5 | Routing | Contains messages that could not be delivered due to a DNS lookup problem or other issues. | false | false | 0 | 7 |
>| 7 | Undetermined | Contains messages that returned an unexpected result from virus scanning or an external command. | false | false | 0 | 7 |
>| 8 | Malformed | Contains messages that were blocked or could not be processed due to problems with encoding. | false | false | 0 | 7 |
>| 9 | Virus | Contains messages that could not be fully unpacked but are classified as containing a virus. | false | false | 0 | 7 |
>| 10 | Spam | Contains messages that could not be fully unpacked but are classified as spam. | false | false | 0 | 7 |
>| 11 | Archiving | Contains messages that could not be delivered to the Archive. | false | false | 0 | 7 |
>| 1000 | Sent History | Contains historic logs for delivered email. | false | true | 0 | 7 |
>| 1001 | DMARC Reports | An archive folder for inbound messages with attached DMARC Reports for the local domains. | false | true | 0 | 7 |
>| 1002 | BEC - Executive Name | Contains messages that match an Executive Name in the From: field. | false | false | 0 | 7 |
>| 1003 | Suspect | Contains messages with attachments deemed suspect, such as undesirable file extensions. | false | false | 0 | 7 |
>| 1004 | Spoofed | Contains messages that are identified as spoofed by the blocked spoofed messages rule. | false | false | 0 | 7 |
>| 1005 | Junk | Generic folder for unwanted messages such as chain letters and hoaxes. | false | false | 0 | 7 |
>| 1006 | Archive In | An archive folder for all inbound messages.  By default, messages are kept for 3 months. | false | true | 3 | 0 |
>| 1007 | Archive Out | An archive folder for all outbound messages.  By default, messages are kept for 3 months. | false | true | 2 | 93 |
>| 1008 | Language | Contains messages blocked because they contain profanity. | false | false | 0 | 7 |
>| 1009 | Parked Large Files | Used for temporarily 'parking' large outbound messages or message mailouts until after business hours. | false | false | 0 | 0 |
>| 1010 | Oversize | Used for quarantining large messages that exceed a threshold. | false | false | 0 | 7 |
>| 1011 | Awaiting Challenge - Response | A folder that holds messages awaiting a response in order to be released. | false | false | 0 | 3 |
>| 1012 | Attachment Type - Executables | Contains messages with identified executable attachments. | false | false | 0 | 7 |
>| 1013 | Attachment Type - Images | Used for messages that contain an attached image. | false | false | 0 | 7 |
>| 1014 | Attachment Type - Video and Sound | Contains messages with sound or video attachments, such as MP3 or AVI files. | false | false | 0 | 7 |
>| 1015 | Attachment Type - Encrypted | Used for messages with encrypted attachments, such as encrypted archive files. | false | false | 0 | 7 |
>| 1016 | Attachment Type - Unknown | Contains messages with binary files of an unknown type. | false | false | 0 | 7 |
>| 1017 | Policy Breaches | Generic folder for messages that breach company policy. | false | false | 0 | 7 |
>| 1018 | Policy Breaches - SEC | Contains messages which may indicate possible SEC compliance issues. | false | false | 0 | 365 |
>| 1019 | Policy Breaches - SOX | Contains messages which trigger keywords which may indicate possible Sarbanes-Oxley compliance issues. | false | false | 0 | 365 |
>| 1020 | Attachment Type - Documents | Contains messages with document attachments, such as PDF files. | false | false | 0 | 7 |
>| 1021 | Suspect Images | Used by the integrated Image Analyzer component to hold images that may be Pornographic. | false | false | 0 | 7 |
>| 1022 | Policy Breaches - HIPAA | Contains messages that trigger health-related keywords which may indicate possible HIPAA compliance issues. | false | false | 0 | 365 |
>| 1023 | Spam - Confirmed | Used where there is a high degree of confidence that the messages are spam.  The folder is not end-user managed. | false | false | 0 | 7 |
>| 1024 | Spam - Scams | Suspected 419, Lottery and other scam emails. | false | false | 0 | 7 |
>| 1025 | Spam - Suspected | Used where the message is suspected as spam.  The folder is  end-user managed. | false | false | 0 | 7 |
>| 1026 | TLS Failures | Contains messages that failed to meet TLS criteria. | false | false | 0 | 7 |
>| 1027 | DKIM Failures | Contains messages that failed to pass DKIM verification. | false | false | 0 | 7 |
>| 1028 | DKIM Signing Failures | Contains messages that could not have a DKIM signature applied. | false | false | 0 | 7 |
>| 1029 | Malware | Messages tagged as having malware by an anti-virus scanner. | false | false | 0 | 7 |
>| 1030 | Malware - Virus Scanner Errors | Messages that have caused the anti-virus scanner to report an error. | false | false | 0 | 7 |
>| 1031 | Malware - Suspected | Messages suspected of having malicious content by one of the gateway's threat filters. | false | false | 0 | 7 |
>| 1032 | SenderID Failures | Contains messages that failed to pass SenderID verification. | false | false | 0 | 7 |
>| 1033 | Suspect URLs | Contains messages that include suspect URLs. | false | false | 0 | 7 |
>| 1034 | Malware - AMAX | Contains messages suspected of having malicious content by the Advanced Malware and Exploit Detection (AMAX) filter. | false | false | 0 | 7 |
>| 1035 | Malformed PDF | Contains messages with PDF attachments that are malformed or corrupt. | false | false | 0 | 7 |
>| 1036 | DMARC Failures - Quarantine policy | Contains messages that failed to pass DMARC verification, where the DMARC policy for message disposition was "quarantine". | false | false | 0 | 7 |
>| 1037 | DMARC Failures - Reject policy | Contains messages that failed to pass DMARC verification, where the DMARC policy for message disposition was "reject". | false | false | 0 | 7 |
>| 1038 | BEC - Fraud Filter | Contains messages detected by the BEC Fraud Filter. | false | false | 0 | 7 |
>| 1039 | BEC - Domain Similarity | Contains messages where the From: domain is similar  to a local domain. | false | false | 0 | 7 |


### trustwave-seg-list-quarantine-folders-with-day-info
***
Gets a list of folders with current day information.


#### Base Command

`trustwave-seg-list-quarantine-folders-with-day-info`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TrustwaveSEG.Folder.dayItems | Unknown | The items of the day for the folder. | 
| TrustwaveSEG.Folder.description | String | The description of the folder. | 
| TrustwaveSEG.Folder.folderId | Number | The ID of the folder. | 
| TrustwaveSEG.Folder.folderType | Number | The type of the folder. | 
| TrustwaveSEG.Folder.iconIndex | Number | The icon index of the folder. | 
| TrustwaveSEG.Folder.isDeleted | Boolean | Whether the folder is deleted. | 
| TrustwaveSEG.Folder.isFingerprintingEnabled | Boolean | Whether fingerprinting is enabled for the folder. | 
| TrustwaveSEG.Folder.isPassThru | Boolean | Whether pass thru is enabled for the folder. | 
| TrustwaveSEG.Folder.isPublishedInbound | Boolean | Whether the folder is published inbound. | 
| TrustwaveSEG.Folder.isPublishedOutbound | Boolean | Whether the folder is published outbound. | 
| TrustwaveSEG.Folder.isReadOnly | Boolean | Whether the is folder read-only. | 
| TrustwaveSEG.Folder.name | String | The name of the folder. | 
| TrustwaveSEG.Folder.numFiles | Number | The number of files in the folder. | 
| TrustwaveSEG.Folder.parentId | Number | The parent ID of the folder. | 
| TrustwaveSEG.Folder.path | String | The path of the folder. | 
| TrustwaveSEG.Folder.retention | Number | The retention of the folder. | 
| TrustwaveSEG.Folder.securityDescription | String | The security description of the folder. | 


#### Command Example
```!trustwave-seg-list-quarantine-folders-with-day-info```

#### Context Example
```json
{
    "TrustwaveSEG": {
        "Folder": [
            {
                "dayItems": [
                    {
                        "endTime": 1619125200,
                        "numFiles": 2,
                        "startTime": 1619038800
                    }
                ],
                "description": "An archive folder for all outbound messages.  By default, messages are kept for 3 months.",
                "folderId": 1007,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": true,
                "name": "Archive Out",
                "numFiles": 2,
                "parentId": 1,
                "path": "A11F07EA-7569-4596-9BC5-B4A25D428BAE",
                "retention": 93,
                "securityDescription": ""
            },
            {
                "dayItems": null,
                "description": "Contains messages blocked because they contain profanity.",
                "folderId": 1008,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Language",
                "numFiles": 0,
                "parentId": 1,
                "path": "6F1422E1-CDB6-4669-ACC7-794CC0669663",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "dayItems": null,
                "description": "",
                "folderId": 1,
                "folderType": 4,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Folders",
                "numFiles": 5,
                "parentId": 0,
                "path": "",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "dayItems": null,
                "description": "Used for temporarily 'parking' large outbound messages or message mailouts until after business hours.",
                "folderId": 1009,
                "folderType": 2,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Parked Large Files",
                "numFiles": 0,
                "parentId": 1,
                "path": "350EC7AE-54FF-4106-903C-79871A72E6BC",
                "retention": 0,
                "securityDescription": ""
            },
            {
                "dayItems": null,
                "description": "",
                "folderId": 2,
                "folderType": 3,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Mail Recycle Bin",
                "numFiles": 0,
                "parentId": 1,
                "path": "",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "dayItems": null,
                "description": "Used for quarantining large messages that exceed a threshold.",
                "folderId": 1010,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Oversize",
                "numFiles": 0,
                "parentId": 1,
                "path": "821EF706-6C63-4F56-8E4C-2E5D18F4FAFA",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "dayItems": null,
                "description": "",
                "folderId": 3,
                "folderType": 4,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Dead Letters",
                "numFiles": 0,
                "parentId": 1,
                "path": "DeadLetter",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "dayItems": null,
                "description": "A folder that holds messages awaiting a response in order to be released.",
                "folderId": 1011,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Awaiting Challenge - Response",
                "numFiles": 0,
                "parentId": 1,
                "path": "E6C18E25-6C63-4740-8783-39A8E9818844",
                "retention": 3,
                "securityDescription": ""
            },
            {
                "dayItems": null,
                "description": "Contains messages that could not be processed due to file corruption or other problems with structure.",
                "folderId": 4,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Unpacking",
                "numFiles": 0,
                "parentId": 3,
                "path": "Unpacking",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "dayItems": null,
                "description": "Contains messages with identified executable attachments.",
                "folderId": 1012,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Attachment Type - Executables",
                "numFiles": 0,
                "parentId": 1,
                "path": "874AE4BA-F735-4067-AC91-DC3453AFC685",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "dayItems": null,
                "description": "Contains messages that could not be delivered due to a DNS lookup problem or other issues.",
                "folderId": 5,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Routing",
                "numFiles": 0,
                "parentId": 3,
                "path": "Routing",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "dayItems": null,
                "description": "Used for messages that contain an attached image.",
                "folderId": 1013,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Attachment Type - Images",
                "numFiles": 0,
                "parentId": 1,
                "path": "C004A276-EAEB-4251-ADEC-494FAF0CB713",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "dayItems": null,
                "description": "Contains messages with sound or video attachments, such as MP3 or AVI files.",
                "folderId": 1014,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Attachment Type - Video and Sound",
                "numFiles": 0,
                "parentId": 1,
                "path": "B0CD505E-8A44-434B-8194-E65976CDB4D9",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "dayItems": null,
                "description": "Contains messages that returned an unexpected result from virus scanning or an external command.",
                "folderId": 7,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Undetermined",
                "numFiles": 0,
                "parentId": 3,
                "path": "Undetermined",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "dayItems": null,
                "description": "Used for messages with encrypted attachments, such as encrypted archive files.",
                "folderId": 1015,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Attachment Type - Encrypted",
                "numFiles": 0,
                "parentId": 1,
                "path": "298D738E-7577-4A91-9E6F-03ED0C817F16",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "dayItems": null,
                "description": "Contains messages that were blocked or could not be processed due to problems with encoding.",
                "folderId": 8,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Malformed",
                "numFiles": 0,
                "parentId": 3,
                "path": "Malformed",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "dayItems": null,
                "description": "Contains messages with binary files of an unknown type.",
                "folderId": 1016,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Attachment Type - Unknown",
                "numFiles": 0,
                "parentId": 1,
                "path": "9A978764-CC8C-46F3-892A-D9E663246046",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "dayItems": null,
                "description": "Contains messages that could not be fully unpacked but are classified as containing a virus.",
                "folderId": 9,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Virus",
                "numFiles": 0,
                "parentId": 3,
                "path": "Virus",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "dayItems": null,
                "description": "Generic folder for messages that breach company policy.",
                "folderId": 1017,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Policy Breaches",
                "numFiles": 0,
                "parentId": 1,
                "path": "5FD9C657-C416-410B-8FA3-EB2BB2709DDE",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "dayItems": null,
                "description": "Contains messages that could not be fully unpacked but are classified as spam.",
                "folderId": 10,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Spam",
                "numFiles": 0,
                "parentId": 3,
                "path": "Spam",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "dayItems": null,
                "description": "Contains messages which may indicate possible SEC compliance issues.",
                "folderId": 1018,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Policy Breaches - SEC",
                "numFiles": 0,
                "parentId": 1,
                "path": "290D7E3C-79EF-4E9C-8F2F-DCCBF41A2C9D",
                "retention": 365,
                "securityDescription": ""
            },
            {
                "dayItems": null,
                "description": "Contains messages that could not be delivered to the Archive.",
                "folderId": 11,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Archiving",
                "numFiles": 0,
                "parentId": 3,
                "path": "Archiving",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "dayItems": null,
                "description": "Contains messages which trigger keywords which may indicate possible Sarbanes-Oxley compliance issues.",
                "folderId": 1019,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Policy Breaches - SOX",
                "numFiles": 0,
                "parentId": 1,
                "path": "8DD88244-BBA9-4100-9F54-62C37C4C3C64",
                "retention": 365,
                "securityDescription": ""
            },
            {
                "dayItems": null,
                "description": "Contains messages with document attachments, such as PDF files.",
                "folderId": 1020,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Attachment Type - Documents",
                "numFiles": 0,
                "parentId": 1,
                "path": "FECF5729-15B7-4530-BC15-2D22C98EB9A6",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "dayItems": null,
                "description": "Used by the integrated Image Analyzer component to hold images that may be Pornographic.",
                "folderId": 1021,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Suspect Images",
                "numFiles": 0,
                "parentId": 1,
                "path": "0E59FDA1-F197-4072-A8BC-3EF514E2E682",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "dayItems": null,
                "description": "Contains messages that trigger health-related keywords which may indicate possible HIPAA compliance issues.",
                "folderId": 1022,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Policy Breaches - HIPAA",
                "numFiles": 0,
                "parentId": 1,
                "path": "D3062553-A54C-48DC-9447-372EE2268CB6",
                "retention": 365,
                "securityDescription": ""
            },
            {
                "dayItems": null,
                "description": "Used where there is a high degree of confidence that the messages are spam.  The folder is not end-user managed.",
                "folderId": 1023,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Spam - Confirmed",
                "numFiles": 0,
                "parentId": 1,
                "path": "3EFF33E4-22C3-41EA-98D7-74E3BB6357FD",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "dayItems": null,
                "description": "Suspected 419, Lottery and other scam emails.",
                "folderId": 1024,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Spam - Scams",
                "numFiles": 0,
                "parentId": 1,
                "path": "C95F143E-B4CD-4A10-9E3D-6E096CD19908",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "dayItems": null,
                "description": "Used where the message is suspected as spam.  The folder is  end-user managed.",
                "folderId": 1025,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": true,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Spam - Suspected",
                "numFiles": 0,
                "parentId": 1,
                "path": "335E332D-57D4-4D3A-BE50-C620E9D63151",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "dayItems": null,
                "description": "Contains messages that failed to meet TLS criteria.",
                "folderId": 1026,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "TLS Failures",
                "numFiles": 0,
                "parentId": 1,
                "path": "192C2502-065C-48B6-BF0C-091C09CA9131",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "dayItems": null,
                "description": "Contains messages that failed to pass DKIM verification.",
                "folderId": 1027,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "DKIM Failures",
                "numFiles": 0,
                "parentId": 1,
                "path": "1AE86AF4-44FC-411D-95E5-20B8F3D0D55E",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "dayItems": null,
                "description": "Contains messages that could not have a DKIM signature applied.",
                "folderId": 1028,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "DKIM Signing Failures",
                "numFiles": 0,
                "parentId": 1,
                "path": "1F1EFD91-6E75-4DE8-B277-13C4997BE17F",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "dayItems": null,
                "description": "Messages tagged as having malware by an anti-virus scanner.",
                "folderId": 1029,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Malware",
                "numFiles": 0,
                "parentId": 1,
                "path": "C9A5C59E-AA24-472B-9B39-A374354F0D05",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "dayItems": null,
                "description": "Messages that have caused the anti-virus scanner to report an error.",
                "folderId": 1030,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Malware - Virus Scanner Errors",
                "numFiles": 0,
                "parentId": 1,
                "path": "23AFE871-65F2-4C91-B02B-942C96AB73AB",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "dayItems": null,
                "description": "Messages suspected of having malicious content by one of the gateway's threat filters.",
                "folderId": 1031,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Malware - Suspected",
                "numFiles": 0,
                "parentId": 1,
                "path": "C0FE5CD3-71EF-4A94-B36D-CA319D674A5D",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "dayItems": null,
                "description": "Contains messages that failed to pass SenderID verification.",
                "folderId": 1032,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "SenderID Failures",
                "numFiles": 0,
                "parentId": 1,
                "path": "C5510AFE-7119-4138-BD8D-5240BB3A94C4",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "dayItems": null,
                "description": "Contains messages that include suspect URLs.",
                "folderId": 1033,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Suspect URLs",
                "numFiles": 0,
                "parentId": 1,
                "path": "CE15B1F6-0839-4A61-AD0C-D87E625CB14F",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "dayItems": null,
                "description": "Contains messages suspected of having malicious content by the Advanced Malware and Exploit Detection (AMAX) filter.",
                "folderId": 1034,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Malware - AMAX",
                "numFiles": 0,
                "parentId": 1,
                "path": "61075A40-337E-4D4C-9368-48822F579AB8",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "dayItems": null,
                "description": "Contains messages with PDF attachments that are malformed or corrupt.",
                "folderId": 1035,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Malformed PDF",
                "numFiles": 0,
                "parentId": 1,
                "path": "61075A40-337E-4D4C-9368-48822F579AB8",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "dayItems": null,
                "description": "Contains messages that failed to pass DMARC verification, where the DMARC policy for message disposition was \"quarantine\".",
                "folderId": 1036,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "DMARC Failures - Quarantine policy",
                "numFiles": 0,
                "parentId": 1,
                "path": "F6C95742-0EDA-4BE7-9B5D-EE8AA32DBA43",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "dayItems": null,
                "description": "Contains messages that failed to pass DMARC verification, where the DMARC policy for message disposition was \"reject\".",
                "folderId": 1037,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "DMARC Failures - Reject policy",
                "numFiles": 0,
                "parentId": 1,
                "path": "51556EA9-390F-4AC2-B521-38B68BC7F3C9",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "dayItems": null,
                "description": "Contains messages detected by the BEC Fraud Filter.",
                "folderId": 1038,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "BEC - Fraud Filter",
                "numFiles": 0,
                "parentId": 1,
                "path": "13B5A560-257E-4D2C-8665-DE7840D26F2F",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "dayItems": null,
                "description": "Contains messages where the From: domain is similar  to a local domain.",
                "folderId": 1039,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "BEC - Domain Similarity",
                "numFiles": 0,
                "parentId": 1,
                "path": "BE9625E3-2E9A-44A6-8BB4-A4254DFB341F",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "dayItems": null,
                "description": "Contains historic logs for delivered email.",
                "folderId": 1000,
                "folderType": 5,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": true,
                "name": "Sent History",
                "numFiles": 0,
                "parentId": 1,
                "path": "4B7E81EE-9D7B-46E2-B027-ECDDFD26E947",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "dayItems": null,
                "description": "An archive folder for inbound messages with attached DMARC Reports for the local domains.",
                "folderId": 1001,
                "folderType": 6,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": true,
                "name": "DMARC Reports",
                "numFiles": 0,
                "parentId": 1,
                "path": "736A0F9F-A865-4519-A111-DA8A967D45A1",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "dayItems": null,
                "description": "Contains messages that match an Executive Name in the From: field.",
                "folderId": 1002,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "BEC - Executive Name",
                "numFiles": 0,
                "parentId": 1,
                "path": "157803C1-1B20-4415-A92F-FA9D871B768C",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "dayItems": null,
                "description": "Contains messages with attachments deemed suspect, such as undesirable file extensions.",
                "folderId": 1003,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Suspect",
                "numFiles": 0,
                "parentId": 1,
                "path": "ED86938B-A2C4-4260-A4AB-D80BF8CE9C72",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "dayItems": null,
                "description": "Contains messages that are identified as spoofed by the blocked spoofed messages rule.",
                "folderId": 1004,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Spoofed",
                "numFiles": 0,
                "parentId": 1,
                "path": "1AE86AF4-44FC-411D-95E5-20B8F3D0D55E",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "dayItems": null,
                "description": "Generic folder for unwanted messages such as chain letters and hoaxes.",
                "folderId": 1005,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": false,
                "name": "Junk",
                "numFiles": 0,
                "parentId": 1,
                "path": "2A3E6EFE-38D6-438D-84B0-BE4AB2B7EFAD",
                "retention": 7,
                "securityDescription": ""
            },
            {
                "dayItems": null,
                "description": "An archive folder for all inbound messages.  By default, messages are kept for 3 months.",
                "folderId": 1006,
                "folderType": 1,
                "iconIndex": 0,
                "isDeleted": false,
                "isFingerprintingEnabled": false,
                "isPassThru": false,
                "isPublishedInbound": false,
                "isPublishedOutbound": false,
                "isReadOnly": true,
                "name": "Archive In",
                "numFiles": 3,
                "parentId": 1,
                "path": "AA55C8DA-7BE2-4EA4-AD99-BAB37FC598DC",
                "retention": 0,
                "securityDescription": ""
            }
        ]
    }
}
```

#### Human Readable Output

>### Quarantine Folders with Day Info
>|Folder Id|Name|Description|Num Files|Is Deleted|Is Read Only|Retention|
>|---|---|---|---|---|---|---|
>| 1007 | Archive Out | An archive folder for all outbound messages.  By default, messages are kept for 3 months. | 2 | false | true | 93 |


### trustwave-seg-list-day-info-by-quarantine-folder
***
Get the current day information for a folder.


#### Base Command

`trustwave-seg-list-day-info-by-quarantine-folder`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| folder_id | The ID of the folder with quarantine day information. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TrustwaveSEG.DayInfo.endTime | Number | The end time of the day information. | 
| TrustwaveSEG.DayInfo.numFiles | Number | The number of files of the day information. | 
| TrustwaveSEG.DayInfo.startTime | Number | The start time of the day information. | 


#### Command Example
```!trustwave-seg-list-day-info-by-quarantine-folder folder_id=1006```

#### Human Readable Output

>### Quarantine Folder with Day Info. ID: 1006
>**No entries.**


### trustwave-seg-find-quarantine-message
***
Find message by specified parameters.


#### Base Command

`trustwave-seg-find-quarantine-message`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| time_range | An optional time range of the search, i.e., 3 months, 1 week, 1 day ago, etc. | Optional | 
| start_time | Start time of the search in the format: YYYY-mm-ddTHH:MM:SSZ or i.e., 3 months, 1 week, 1 day ago, etc. Given only the start_time, end_time will be set to the current time. | Optional | 
| end_time | End time of the search in the format: YYYY-mm-ddTHH:MM:SSZ or i.e., 3 months, 1 week, 1 day ago, etc. | Optional | 
| max_rows | The number of rows to return from the API. Default to 10. Default is 10. | Optional | 
| folder_id | The ID of the folder in which to search for information (e.g., 1006). | Optional | 
| message_name | The name of the message to search for. | Optional | 
| classification | The classification ID. Can be found by using the classification command (e.g., 37). | Optional | 
| from_user | The email address from which the message was sent. | Optional | 
| to_user | The email address to which the message was sent. | Optional | 
| to_domain | The domain to which the message was sent. | Optional | 
| min_size | The minimum size in bytes of the message (e.g., 0). | Optional | 
| max_size | The maximum size in bytes of the message (e.g., 1024). | Optional | 
| subject | The subject of the message.  (e.g., "some subject"). | Optional | 
| search_history | Whether the search should include the history. Possible values are: true, false. | Optional | 
| forwards | Whether the search should include forwarded messages. Possible values are: true, false. | Optional | 
| block_number | The block number of the message (e.g., 106098471075840). | Optional | 
| search_blank_subject | Whether the search should include messages with a blank subject. Possible values are: true, false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TrustwaveSEG.Message.actionType | Number | The action type of the message. | 
| TrustwaveSEG.Message.blockNumber | Number | The block number of the message. | 
| TrustwaveSEG.Message.blockRecipientIndex | Number | The block recipient index of the message. | 
| TrustwaveSEG.Message.classification | Number | The classification of the message. | 
| TrustwaveSEG.Message.deleted | Number | The number of the deleted message. | 
| TrustwaveSEG.Message.description | String | The description of the message. | 
| TrustwaveSEG.Message.edition | String | The edition of the message. | 
| TrustwaveSEG.Message.folderId | Number | The folder ID of the message. | 
| TrustwaveSEG.Message.hasAttachments | Boolean | Whether the message has attachments. | 
| TrustwaveSEG.Message.messageBody | String | The body of the message. | 
| TrustwaveSEG.Message.messageName | String | The name of the message. | 
| TrustwaveSEG.Message.recipient | String | The recipient of the message. | 
| TrustwaveSEG.Message.sender | String | The sender of the message. | 
| TrustwaveSEG.Message.serverId | Number | The server ID of the message. | 
| TrustwaveSEG.Message.sessionNumber | Number | The session number of the message. | 
| TrustwaveSEG.Message.size | Number | The size of the message. | 
| TrustwaveSEG.Message.subject | String | The subject of the message. | 
| TrustwaveSEG.Message.timeArrived | Number | The time the message arrived. | 
| TrustwaveSEG.Message.timeLogged | Number | The time the message was logged. | 
| TrustwaveSEG.Message.unicodeSubject | String | The unicode subject of the message. | 


#### Command Example
```!trustwave-seg-find-quarantine-message max_rows=10 time_range="3 month"```

#### Context Example
```json
{
    "TrustwaveSEG": {
        "Message": [
            {
                "actionType": 1,
                "blockNumber": 106115282632704,
                "blockRecipientIndex": 0,
                "classification": 37,
                "deleted": 0,
                "description": "- Message Archiving : Archive All Inbound Messages",
                "edition": "6082e3b60013",
                "folderId": 1006,
                "hasAttachments": false,
                "messageBody": "This is the body of the email\r",
                "messageName": "B6082e3b60000",
                "recipient": "test@example.com",
                "sender": "root@localhost.localdomain",
                "serverId": 1,
                "sessionNumber": -474611712,
                "size": 870,
                "subject": "This is the subject line",
                "timeArrived": 1619190710,
                "timeLogged": 1619190710,
                "unicodeSubject": "This is the subject line"
            },
            {
                "actionType": 1,
                "blockNumber": 106112687144960,
                "blockRecipientIndex": 0,
                "classification": 37,
                "deleted": 0,
                "description": "- Message Archiving : Archive All Inbound Messages",
                "edition": "608249030012",
                "folderId": 1006,
                "hasAttachments": false,
                "messageBody": "This is the body of the email\r",
                "messageName": "B608249020000",
                "recipient": "test@example.com",
                "sender": "root@localhost.localdomain",
                "serverId": 1,
                "sessionNumber": 1224933376,
                "size": 870,
                "subject": "This is the subject line",
                "timeArrived": 1619151106,
                "timeLogged": 1619151106,
                "unicodeSubject": "This is the subject line"
            },
            {
                "actionType": 1,
                "blockNumber": 106109128212480,
                "blockRecipientIndex": 0,
                "classification": 38,
                "deleted": 0,
                "description": "- Message Archiving : Archive All Outbound Messages",
                "edition": "608174e50003",
                "folderId": 1007,
                "hasAttachments": false,
                "messageBody": "This is the bodydhgdghdfghgfd54645645645fddfgdgdf\r",
                "messageName": "B608174e50000",
                "recipient": "test@example.com",
                "sender": "root@localhost.localdomain",
                "serverId": 1,
                "sessionNumber": 1961164800,
                "size": 1279,
                "subject": "This isafdsafasgfaiysgfsaidghfuisf   sdgsgsd the subject line",
                "timeArrived": 1619096805,
                "timeLogged": 1619096805,
                "unicodeSubject": "This isafdsafasgfaiysgfsaidghfuisf   sdgsgsd the subject line"
            },
            {
                "actionType": 1,
                "blockNumber": 106106651148288,
                "blockRecipientIndex": 0,
                "classification": 38,
                "deleted": 0,
                "description": "- Message Archiving : Archive All Outbound Messages",
                "edition": "6080e13e0000",
                "folderId": 1007,
                "hasAttachments": false,
                "messageBody": "This is the bodydhgdghdfghgfd54645645645fddfgdgdf\r",
                "messageName": "B6080e1390000",
                "recipient": "test@example.com",
                "sender": "root@localhost.localdomain",
                "serverId": 1,
                "sessionNumber": -516030464,
                "size": 1279,
                "subject": "This isafdsafasgfaiysgfsaidghfuisf   sdgsgsd the subject line",
                "timeArrived": 1619059003,
                "timeLogged": 1619059003,
                "unicodeSubject": "This isafdsafasgfaiysgfsaidghfuisf   sdgsgsd the subject line"
            },
            {
                "actionType": 1,
                "blockNumber": 106098471075840,
                "blockRecipientIndex": 0,
                "classification": 37,
                "deleted": 0,
                "description": "- Message Archiving : Archive All Inbound Messages",
                "edition": "607ef9ae0000",
                "folderId": 1006,
                "hasAttachments": false,
                "messageBody": "This is the body of the email\r",
                "messageName": "B607ef9ac0000",
                "recipient": "test@example.com",
                "sender": "root@localhost.localdomain",
                "serverId": 1,
                "sessionNumber": -106037248,
                "size": 870,
                "subject": "This is the subject line",
                "timeArrived": 1618934189,
                "timeLogged": 1618934189,
                "unicodeSubject": "This is the subject line"
            }
        ]
    }
}
```

#### Human Readable Output

>### Find Quarantine Messages Results
>|Subject|Description|Block Number|Edition|Folder Id|Message Name|Recipient|Server Id|Time Logged|
>|---|---|---|---|---|---|---|---|---|
>| This is the subject line | - Message Archiving : Archive All Inbound Messages | 106115282632704 | 6082e3b60013 | 1006 | B6082e3b60000 | test@example.com | 1 | 1619190710 |
>| This is the subject line | - Message Archiving : Archive All Inbound Messages | 106112687144960 | 608249030012 | 1006 | B608249020000 | test@example.com | 1 | 1619151106 |
>| This isafdsafasgfaiysgfsaidghfuisf   sdgsgsd the subject line | - Message Archiving : Archive All Outbound Messages | 106109128212480 | 608174e50003 | 1007 | B608174e50000 | test@example.com | 1 | 1619096805 |
>| This isafdsafasgfaiysgfsaidghfuisf   sdgsgsd the subject line | - Message Archiving : Archive All Outbound Messages | 106106651148288 | 6080e13e0000 | 1007 | B6080e1390000 | test@example.com | 1 | 1619059003 |
>| This is the subject line | - Message Archiving : Archive All Inbound Messages | 106098471075840 | 607ef9ae0000 | 1006 | B607ef9ac0000 | test@example.com | 1 | 1618934189 |


### trustwave-seg-spiderlabs-forward-quarantine-message-as-spam
***
Forwards a message to Spiderlabs as spam.


#### Base Command

`trustwave-seg-spiderlabs-forward-quarantine-message-as-spam`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| block_number | The block number of the message to search for (e.g., 106098471075840). Can be retrieved from the find message endpoint. | Required | 
| edition | Edition of the message (e.g., "607ef9ae0000"). Can be retrieved from the find message endpoint. | Required | 
| folder_id | Folder ID of the message (e.g., 1006). Can be retrieved from the find message endpoint. | Required | 
| message_name | The name of the message (e.g., "B607ef9ac0000"). Can be retrieved from the find message endpoint. | Required | 
| recipient | The recipient of the message (e.g., email@example.com). Can be retrieved from the find message endpoint. | Required | 
| server_id | The server ID of the message (e.g., 1). Can be retrieved from the find message endpoint. . | Required | 
| time_logged | The time the message was logged (e.g., 1618934189). Can be retrieved from the find message endpoint. . | Required | 
| spam_report_message | The message that should be shown with the message on Spiderlabs. (e.g., "This message is spam..."). | Required | 
| is_spam | Whether the message is spam. Possible values are true, false. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!trustwave-seg-spiderlabs-forward-quarantine-message-as-spam block_number=106098471075840 edition=607ef9ae0000 folder_id=1006 is_spam="true" message_name=B607ef9ac0000 recipient=test@example.com server_id=1 spam_report_notification_from_address="This is a spam" time_logged=1618934189 spam_report_message="This is a spam"```

#### Human Readable Output

>The message was forwarded to Spiderlabs.