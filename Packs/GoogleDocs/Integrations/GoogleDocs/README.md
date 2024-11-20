Use the Google Docs integration to create and modify Google Docs documents.
## Configure GoogleDocs in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| service_account_credentials | Service Account Private Key file contents \(JSON\) | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### google-docs-get-document
***
Returns the document that matches the specified document ID.


#### Base Command

`google-docs-get-document`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| document_id | The document ID of the document to fetch. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleDocs.Title | String | The title of the document. | 
| GoogleDocs.RevisionId | String | The revision ID of the updated document. | 
| GoogleDocs.DocumentId | String | The document ID of the updated document. | 


#### Command Example
```!google-docs-get-document document_id=1MjtBlFLwFNsjVwCF0mZLxpRoblVHjLcR3VmZcUuNvzo```

#### Context Example
```json
{
    "GoogleDocs": {
        "DocumentId": "1MjtBlFLwFNsjVwCF0mZLxpRoblVHjLcR3VmZcUuNvzo",
        "RevisionId": "ALm37BWMd6E3RFLJAI4uq5BdFTiJyeKWjjcVwRdHqv33lE2EWEPv7znT1PmdlB4zLv3xxpTIXlVRJ2Rq71lMCg",
        "Title": "testing"
    }
}
```

#### Human Readable Output

>### The document with the title testing was returned. The results are:
>|DocumentId|RevisionId|Title|
>|---|---|---|
>| 1MjtBlFLwFNsjVwCF0mZLxpRoblVHjLcR3VmZcUuNvzo | ALm37BWMd6E3RFLJAI4uq5BdFTiJyeKWjjcVwRdHqv33lE2EWEPv7znT1PmdlB4zLv3xxpTIXlVRJ2Rq71lMCg | testing |


### google-docs-create-document
***
Creates a document.


#### Base Command

`google-docs-create-document`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| title | The title of the document to create. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleDocs.Title | String | The title of the new document. | 
| GoogleDocs.RevisionId | String | The revision ID of the new document. | 
| GoogleDocs.DocumentId | String | The document ID of the new document. | 


#### Command Example
```!google-docs-create-document title="testing"```

#### Context Example
```json
{
    "GoogleDocs": {
        "DocumentId": "12YHG7OISB99ANM3GTbtK9IveiBxyrndnDGuRyyRiA5U",
        "RevisionId": "ALm37BWqvcEhS-G00EiPhh2ge7RZz4mYof8Fws-lFE5HfBPwILQJ8ZXmTY0XZCB3sg9a1xiTNzU_jJnFewwaHw",
        "Title": "testing"
    }
}
```

#### Human Readable Output

>### The document with the title testing was created. The results are:
>|DocumentId|RevisionId|Title|
>|---|---|---|
>| 12YHG7OISB99ANM3GTbtK9IveiBxyrndnDGuRyyRiA5U | ALm37BWqvcEhS-G00EiPhh2ge7RZz4mYof8Fws-lFE5HfBPwILQJ8ZXmTY0XZCB3sg9a1xiTNzU_jJnFewwaHw | testing |


### google-docs-update-document
***
Updates the document with the specified document ID.


#### Base Command

`google-docs-update-document`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| document_id | The document ID of the document to update. | Required | 
| actions | Updates to the document in the format: action1{param1,param2,...};action2{param1,param2,...}. | Required | 
| required_revision_id | The target revision ID of the document to which the write request will be applied. If a newer revision exists you will receive an error. If you specify the target_revision_id argument, you cannot use this argument. | Optional | 
| target_revision_id | The target revision ID of the document to which the write request will be applied. If a newer revision exists you will receive an error. If you specify the required_revision_id argument, you cannot use this argument. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleDocs.Title | String | The title of the updated. | 
| GoogleDocs.RevisionId | String | The revision ID of the updated document. | 
| GoogleDocs.DocumentId | Unknown | The document ID of the updated document. | 


#### Command Example
```!google-docs-update-document document_id=1MjtBlFLwFNsjVwCF0mZLxpRoblVHjLcR3VmZcUuNvzo actions=insertText{1,hey};insertText{3,hello}```

#### Context Example
```json
{
    "GoogleDocs": {
        "DocumentId": "1MjtBlFLwFNsjVwCF0mZLxpRoblVHjLcR3VmZcUuNvzo",
        "RevisionId": "ALm37BWCZhPcqsQ0g1oatbiEtHz2vLXIkZwn9Rt-y0riIUKiuQOfvByrPlJsDW9uW3DRkSwZ7vLBgLgDrrnW9g",
        "Title": "testing"
    }
}
```

#### Human Readable Output

>### The document with the title testing and actions insertText{1,hey};insertText{3,hello} was updated. the results are:
>|DocumentId|RevisionId|Title|
>|---|---|---|
>| 1MjtBlFLwFNsjVwCF0mZLxpRoblVHjLcR3VmZcUuNvzo | ALm37BWCZhPcqsQ0g1oatbiEtHz2vLXIkZwn9Rt-y0riIUKiuQOfvByrPlJsDW9uW3DRkSwZ7vLBgLgDrrnW9g | testing |
