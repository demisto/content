Manage Secrets and Protect Sensitive Data through Keeper Vault.
This integration was integrated and tested with version 16.3.5 of Keeper Secrets Manager.

## Configure Keeper Secrets Manager in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| KSM Configuration | The KSM config to use for connection. | True |
| Trust any certificate (not secure) | When 'trust any certificate' is selected, the integration ignores TLS/SSL certificate validation errors. Use to test connection issues or connect to a server without a valid certificate. | False |
| Fetches credentials | Fetches credentials from login records. | False |
| Concat username to credential object name | Use to make the credential object unique in case of duplicate names in different folders/secrets. | False |
| A comma-separated list of credential names to fetch. | Partial names are not supported. If left empty, all credentials will be fetched. | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### ksm-find-files
***
Search for records by full or partial file name match.


#### Base Command

`ksm-find-files`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_name | File name text to search for. | Required | 
| partial_match | Search for partial file name match. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| KeeperSecretsManager.Files.record_uid | String | Record UID. | 
| KeeperSecretsManager.Files.file_uid | String | File UID. | 
| KeeperSecretsManager.Files.file_name | String | File Name. | 
| KeeperSecretsManager.Files.file_size | String | File Size. | 

#### Command example
```!ksm-find-files file_name="blank.txt"```
#### Context Example
```json
{
    "KeeperSecretsManager": {
        "Files": [
            {
                "file_name": "blank.txt",
                "file_size": 5,
                "file_uid": "Z8F-lSBHmTiMMDQrRiBjUA",
                "record_uid": "PNby7a3Mrh4OfPdkpdfFsA"
            },
            {
                "file_name": "blank.txt",
                "file_size": 5,
                "file_uid": "xdsQvfDzD-W38_alIwJnMg",
                "record_uid": "4FTOiJx-m31hDIlmief1Cg"
            }
        ]
    }
}
```

#### Human Readable Output

>### Records with attachments
>### Record Details
>|file_name|file_size|file_uid|record_uid|
>|---|---|---|---|
>| blank.txt | 5 | Z8F-lSBHmTiMMDQrRiBjUA | PNby7a3Mrh4OfPdkpdfFsA |
>| blank.txt | 5 | xdsQvfDzD-W38_alIwJnMg | 4FTOiJx-m31hDIlmief1Cg |


### ksm-find-records
***
Search for records by full or partial title match.


#### Base Command

`ksm-find-records`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| title | Title text to search for. | Required | 
| partial_match | Search for partial title match. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| KeeperSecretsManager.Records.uid | String | Record UID. | 
| KeeperSecretsManager.Records.type | String | Record Type. | 
| KeeperSecretsManager.Records.title | String | Record Title. | 

#### Command example
```!ksm-find-records title="file"```
#### Context Example
```json
{
    "KeeperSecretsManager": {
        "Records": [
            {
                "uid": "WcizqXQGsk0Jho48Mn52MQ",
                "type": "file",
                "title": "files1"
            },
            {
                "uid": "Px5xVljXRZ1dPYMQ9Yv05Q",
                "type": "file",
                "title": "files2"
            }
        ]
    }
}
```

#### Human Readable Output

>### Records
>### Record Details
>|uid|type|tite|
>|---|---|---|
>| WcizqXQGsk0Jho48Mn52MQ | file | files1 |
>| Px5xVljXRZ1dPYMQ9Yv05Q | file | files2 |


### ksm-get-field
***
Use this command to get field value from Keeper record.


#### Base Command

`ksm-get-field`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| notation | Keeper KSM notation URI. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| KeeperSecretsManager.Field.field | String | Extracted field value. | 

#### Command example
```!ksm-get-field notation="keeper://6LJgiVzzD4ZJuxQYj_wN9A/field/login"```
#### Context Example
```json
{
    "KeeperSecretsManager": {
        "Field": "admin"
    }
}
```

#### Human Readable Output

>## admin

### ksm-get-file
***
Use this command to fetch the file attachment as a File.


#### Base Command

`ksm-get-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_uid | File UID to search for. | Required | 
| record_uid | Record UID to search for files. Search all records if empty. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!ksm-get-file file_uid="bZs6l8Hx9zkrRPYVFyuYLA"```
#### Context Example
```json
{
    "File": {
        "EntryID": "36@21232f297a57a5a743894a0e4a801fc3$&$9b10a24b-f008-42e0-8554-d24397e91996",
        "Extension": "txt",
        "Info": "text/plain; charset=utf-8",
        "MD5": "8e15625d6c158ec48f374efb77bd2714",
        "Name": "blank.txt",
        "SHA1": "6184d6847d594ec75c4c07514d4bb490d5e166df",
        "SHA256": "ff71cf74abb3ccb005b8b64371725db15edc42c1ad33413bbe561b2da3c85ef9",
        "SHA512": "c7503ab487c392e8cbbe756fd7340bd83214c351dfd48a2c597285267621976a5e321fa88923917b8a2fb6895727da0a42123233258b4da485b0de7c91ba8610",
        "SSDeep": "3:wO:wO",
        "Size": 5,
        "Type": "ASCII text, with no line terminators"
    }
}
```

#### Human Readable Output



### ksm-get-infofile
***
Use this command to fetch the file attachment as an Info File.


#### Base Command

`ksm-get-infofile`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_uid | File UID to search for. | Required | 
| record_uid | Record UID to search for files. Search all records if empty. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!ksm-get-infofile file_uid="bZs6l8Hx9zkrRPYVFyuYLA"```
#### Context Example
```json
{
    "InfoFile": {
        "EntryID": "40@21232f297a57a5a743894a0e4a801fc3$&$9b10a24b-f008-42e0-8554-d24397e91996",
        "Extension": "txt",
        "Info": "text/plain; charset=utf-8",
        "Name": "blank.txt",
        "Size": 5,
        "Type": "ASCII text, with no line terminators"
    }
}
```

#### Human Readable Output



### ksm-list-credentials
***
Use this command to list all credentials in your Keeper Vault that are shared to the KSM application.


#### Base Command

`ksm-list-credentials`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| KeeperSecretsManager.Creds.uid | String | Record UID. | 
| KeeperSecretsManager.Creds.title | String | Record Title. | 
| KeeperSecretsManager.Creds.name | String | Username. | 

#### Command example
```!ksm-list-credentials```
#### Context Example
```json
{
    "KeeperSecretsManager": {
        "Creds": [
            {
                "name": "IIS Admin",
                "uid": "6LJgiVzzD4ZJuxQYj_wN9A",
                "user": "admin"
            },
            {
                "name": "nginx Admin",
                "uid": "7W6exgzq_OeVF6Xh1EJ29g",
                "user": "admin"
            }
        ]
    }
}
```

#### Human Readable Output

>### Credentials
>### Credential Details
>|name|uid|user|
>|---|---|---|
>| IIS Admin | 6LJgiVzzD4ZJuxQYj_wN9A | admin |
>| nginx Admin | 7W6exgzq_OeVF6Xh1EJ29g | admin |


### ksm-list-files
***
Use this command to list all records that have file attachments.


#### Base Command

`ksm-list-files`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| record_uids | A comma-separated list of record UIDs to search. If left empty all records with file attachments will be listed. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| KeeperSecretsManager.Files.record_uid | String | Record UID. | 
| KeeperSecretsManager.Files.file_uid | String | File UID. | 
| KeeperSecretsManager.Files.file_name | String | File Name. | 
| KeeperSecretsManager.Files.file_size | String | File Size. | 

#### Command example
```!ksm-list-files```
#### Context Example
```json
{
    "KeeperSecretsManager": {
        "Files": [
            {
                "file_name": "blank.txt",
                "file_size": 5,
                "file_uid": "bZs6l8Hx9zkrRPYVFyuYLA",
                "record_uid": "RXd1m_fKO2XnAWzeUawM5A"
            },
            {
                "file_name": "blank.txt",
                "file_size": 5,
                "file_uid": "xdsQvfDzD-W38_alIwJnMg",
                "record_uid": "4FTOiJx-m31hDIlmief1Cg"
            }
        ]
    }
}
```

#### Human Readable Output

>### Records with attachments
>### Record Details
>|file_name|file_size|file_uid|record_uid|
>|---|---|---|---|
>| blank.txt | 5 | bZs6l8Hx9zkrRPYVFyuYLA | RXd1m_fKO2XnAWzeUawM5A |
>| blank.txt | 5 | xdsQvfDzD-W38_alIwJnMg | 4FTOiJx-m31hDIlmief1Cg |


### ksm-list-records
***
Use this command to list all records from your Keeper Vault that are shared to the application.


#### Base Command

`ksm-list-records`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| KeeperSecretsManager.Records.uid | String | Record UID. | 
| KeeperSecretsManager.Records.type | String | Record Type. | 
| KeeperSecretsManager.Records.title | String | Record Title. | 

#### Command example
```!ksm-list-records```
#### Context Example
```json
{
    "KeeperSecretsManager": {
        "Records": [
            {
                "title": "files2",
                "type": "file",
                "uid": "RXd1m_fKO2XnAWzeUawM5A"
            },
            {
                "title": "files1",
                "type": "file",
                "uid": "4FTOiJx-m31hDIlmief1Cg"
            },
            {
                "title": "IIS Admin",
                "type": "login",
                "uid": "6LJgiVzzD4ZJuxQYj_wN9A"
            },
            {
                "title": "nginx Admin",
                "type": "login",
                "uid": "7W6exgzq_OeVF6Xh1EJ29g"
            }
        ]
    }
}
```

#### Human Readable Output

>### Records
>### Record Details
>|title|type|uid|
>|---|---|---|
>| files2 | file | RXd1m_fKO2XnAWzeUawM5A |
>| files1 | file | 4FTOiJx-m31hDIlmief1Cg |
>| IIS Admin | login | 6LJgiVzzD4ZJuxQYj_wN9A |
>| nginx Admin | login | 7W6exgzq_OeVF6Xh1EJ29g |
