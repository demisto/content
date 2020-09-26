An Integration with a code analysis platform for finding zero-days and preventing critical vulnerabilities
This integration was integrated and tested with version 1.0 of LGTM
## Configure LGTM on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for LGTM.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server URL \(e.g. https://example.net\) | True |
| apikey | API Token | True |
| isFetch | Fetch incidents | False |
| incidentType | Incident type | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### lgtm-get-project-by-url
***
Get Project by Org and Name Identifiers


#### Base Command

`lgtm-get-project-by-url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| provider | Code Repo Provider , example : g for github | Required | 
| org | Code Repo Organization | Required | 
| name | Code Repo Name | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LGTM.Projects | Unknown | LGTM Projects | 


#### Command Example
```!lgtm-get-project-by-url provider="g" org="my-devsecops" name="moon"```

#### Context Example
```
{
    "LGTM": {
        "Projects": [
            {
                "id": 1512319787549,
                "languages": [
                    {
                        "alerts": 11,
                        "analysis-date": "2020-09-25T04:12:27.131+0000",
                        "commit-date": "2020-09-09T14:53:17.000+0000",
                        "commit-id": "39eb3dc0c7e86d0b943df1be922b173068010bf5",
                        "grade": "E",
                        "language": "python",
                        "lines": 127,
                        "status": "success"
                    }
                ],
                "name": "my-devsecops/moon",
                "url": "https://lgtm.com/projects/g/my-devsecops/moon"
            }
        ]
    }
}
```

#### Human Readable Output

>### LGTM - Project Details
>|id|languages|name|url|
>|---|---|---|---|
>| 1512319787549 | {'language': 'python', 'status': 'success', 'alerts': 11, 'lines': 127, 'commit-id': '39eb3dc0c7e86d0b943df1be922b173068010bf5', 'commit-date': '2020-09-09T14:53:17.000+0000', 'analysis-date': '2020-09-25T04:12:27.131+0000', 'grade': 'E'} | my-devsecops/moon | https://lgtm.com/projects/g/my-devsecops/moon |


### lgtm-get-project-by-id
***
Get Project by LGTM ID


#### Base Command

`lgtm-get-project-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | LGTM Project ID, example: 1511896439667 | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LGTM.Projects | Unknown | LGTM Projects | 


#### Command Example
```!lgtm-get-project-by-id id=1512319787549```

#### Context Example
```
{
    "LGTM": {
        "Projects": [
            {
                "id": 1512319787549,
                "languages": [
                    {
                        "alerts": 11,
                        "analysis-date": "2020-09-25T04:12:27.131+0000",
                        "commit-date": "2020-09-09T14:53:17.000+0000",
                        "commit-id": "39eb3dc0c7e86d0b943df1be922b173068010bf5",
                        "grade": "E",
                        "language": "python",
                        "lines": 127,
                        "status": "success"
                    }
                ],
                "name": "my-devsecops/moon",
                "url": "https://lgtm.com/projects/g/my-devsecops/moon"
            }
        ]
    }
}
```

#### Human Readable Output

>### LGTM - Project Details
>|id|languages|name|url|
>|---|---|---|---|
>| 1512319787549 | {'language': 'python', 'status': 'success', 'alerts': 11, 'lines': 127, 'commit-id': '39eb3dc0c7e86d0b943df1be922b173068010bf5', 'commit-date': '2020-09-09T14:53:17.000+0000', 'analysis-date': '2020-09-25T04:12:27.131+0000', 'grade': 'E'} | my-devsecops/moon | https://lgtm.com/projects/g/my-devsecops/moon |


### lgtm-get-project-config
***
Get Extraction and Analysis Config by Project ID


#### Base Command

`lgtm-get-project-config`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | LGTM Project ID | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LGTM.Configs | Unknown | LGTM Project Configurations | 


#### Command Example
``` ```

#### Human Readable Output



### lgtm-run-commit-analysis
***
Run LGTM Analysis on Specific Commit


#### Base Command

`lgtm-run-commit-analysis`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| commit_id | Commit ID to Analyze | Required | 
| project_id | LGTM Project ID | Required | 
| language | LGTM Coding Language | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LGTM.Tasks | Unknown | LGTM Analysis Results | 


#### Command Example
```!lgtm-run-commit-analysis commit_id="39eb3dc0c7e86d0b943df1be922b173068010bf5" project_id="1512319787549" language="python"```

#### Context Example
```
{
    "LGTM": {
        "Analysis": [
            [
                {
                    "commit-id": "39eb3dc0c7e86d0b943df1be922b173068010bf5",
                    "id": "927d89b0392c332575d30a73ca0298317d68477c",
                    "languages": [
                        {
                            "alerts": 11,
                            "analysis-date": "2020-09-26T10:51:50.333+0000",
                            "commit-date": "2020-09-09T14:53:17.000+0000",
                            "commit-id": "39eb3dc0c7e86d0b943df1be922b173068010bf5",
                            "language": "python",
                            "lines": 127,
                            "status": "success"
                        }
                    ],
                    "log-url": "https://lgtm.com/projects/g/my-devsecops/moon/logs/analysis/927d89b0392c332575d30a73ca0298317d68477c",
                    "project": {
                        "id": 1512319787549,
                        "name": "my-devsecops/moon",
                        "url": "https://lgtm.com/projects/g/my-devsecops/moon",
                        "url-identifier": "g/my-devsecops/moon"
                    },
                    "results-url": "https://lgtm.com/projects/g/my-devsecops/moon/analysis/927d89b0392c332575d30a73ca0298317d68477c/files"
                }
            ]
        ]
    }
}
```

#### Human Readable Output

>### LGTM - Code Analysis Results
>|Analysis Results|
>|---|
>| {'id': '927d89b0392c332575d30a73ca0298317d68477c', 'project': {'id': 1512319787549, 'url-identifier': 'g/my-devsecops/moon', 'name': 'my-devsecops/moon', 'url': 'https://lgtm.com/projects/g/my-devsecops/moon'}, 'commit-id': '39eb3dc0c7e86d0b943df1be922b173068010bf5', 'languages': [{'language': 'python', 'status': 'success', 'alerts': 11, 'lines': 127, 'commit-id': '39eb3dc0c7e86d0b943df1be922b173068010bf5', 'commit-date': '2020-09-09T14:53:17.000+0000', 'analysis-date': '2020-09-26T10:51:50.333+0000'}], 'log-url': 'https://lgtm.com/projects/g/my-devsecops/moon/logs/analysis/927d89b0392c332575d30a73ca0298317d68477c', 'results-url': 'https://lgtm.com/projects/g/my-devsecops/moon/analysis/927d89b0392c332575d30a73ca0298317d68477c/files'} |


### lgtm-get-analysis-status
***
Get Analysis Results


#### Base Command

`lgtm-get-analysis-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| analysis_id | LGTM Analysis Task ID | Optional | 
| commit_id | Commit ID | Optional | 
| project_id | Project ID | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!lgtm-get-analysis-status analysis_id="927d89b0392c332575d30a73ca0298317d68477c"```

#### Context Example
```
{
    "LGTM": {
        "Analysis": {
            "commit-id": "39eb3dc0c7e86d0b943df1be922b173068010bf5",
            "id": "927d89b0392c332575d30a73ca0298317d68477c",
            "languages": [
                {
                    "alerts": 11,
                    "analysis-date": "2020-09-26T10:51:50.333+0000",
                    "commit-date": "2020-09-09T14:53:17.000+0000",
                    "commit-id": "39eb3dc0c7e86d0b943df1be922b173068010bf5",
                    "language": "python",
                    "lines": 127,
                    "status": "success"
                }
            ],
            "log-url": "https://lgtm.com/projects/g/my-devsecops/moon/logs/analysis/927d89b0392c332575d30a73ca0298317d68477c",
            "project": {
                "id": 1512319787549,
                "name": "my-devsecops/moon",
                "url": "https://lgtm.com/projects/g/my-devsecops/moon",
                "url-identifier": "g/my-devsecops/moon"
            },
            "results-url": "https://lgtm.com/projects/g/my-devsecops/moon/analysis/927d89b0392c332575d30a73ca0298317d68477c/files"
        }
    }
}
```

#### Human Readable Output

>### LGTM - Code Analysis Status
>|Analysis Status|
>|---|
>| success |


### lgtm-run-project-query
***
Run CodeQL Query on A Project


#### Base Command

`lgtm-run-project-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | LGTM Project ID | Required | 
| language | Code Language | Required | 
| query | CodeQL Query List Name | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LGTM.Queries | Unknown | LGTM Queries Results | 


#### Command Example
```!lgtm-run-project-query project_id="1512319787549" language="python" query=${lists.CodeQL-Queries-SQL_Injection}```

#### Context Example
```
{
    "LGTM": {
        "Queries": [
            [
                {
                    "id": 1512683436389,
                    "status": "pending",
                    "task-result": {
                        "id": "2586147600888057373",
                        "result-url": "https://lgtm.com/query/2586147600888057373",
                        "stats": {
                            "failed": 0,
                            "pending": 0,
                            "success-with-result": 0,
                            "success-without-result": 0,
                            "successful": 0
                        }
                    },
                    "task-result-url": "https://lgtm.com/api/v1.0/queryjobs/2586147600888057373",
                    "task-type": "queryjob"
                }
            ]
        ]
    }
}
```

#### Human Readable Output

>### LGTM - Query Analysis Results
>|Query Results|
>|---|
>| {'id': 1512683436389, 'status': 'pending', 'task-type': 'queryjob', 'task-result': {'id': '2586147600888057373', 'stats': {'successful': 0, 'success-with-result': 0, 'success-without-result': 0, 'failed': 0, 'pending': 0}, 'result-url': 'https://lgtm.com/query/2586147600888057373'}, 'task-result-url': 'https://lgtm.com/api/v1.0/queryjobs/2586147600888057373'} |


### lgtm-get-alerts-details
***
Get Alerts Details by Analysis ID


#### Base Command

`lgtm-get-alerts-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| analysis_id | LGTM Analysis ID | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LGTM.Alerts | Unknown | LGTM Alerts Details | 


#### Command Example
```!lgtm-get-alerts-details analysis_id="927d89b0392c332575d30a73ca0298317d68477c"```

#### Context Example
```
{
    "LGTM": {
        "Alerts": [
            {
                "alert": {
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "index": 0,
                                    "uri": "module1.py",
                                    "uriBaseId": "%SRCROOT%"
                                },
                                "region": {
                                    "endColumn": 70,
                                    "startColumn": 23,
                                    "startLine": 112
                                }
                            }
                        }
                    ],
                    "message": {
                        "text": "Call to [function load_from_config](1) with too many arguments; should be no more than 1."
                    },
                    "partialFingerprints": {
                        "primaryLocationLineHash": "a8e1daf8b5008d1d:1",
                        "primaryLocationStartColumnFingerprint": "18"
                    },
                    "relatedLocations": [
                        {
                            "id": 1,
                            "message": {
                                "text": "function load_from_config"
                            },
                            "physicalLocation": {
                                "artifactLocation": {
                                    "index": 0,
                                    "uri": "module1.py",
                                    "uriBaseId": "%SRCROOT%"
                                },
                                "region": {
                                    "endColumn": 28,
                                    "startLine": 101
                                }
                            }
                        }
                    ],
                    "ruleId": "com.lgtm/python-queries:py/call/wrong-arguments",
                    "ruleIndex": 0
                },
                "analysisId": "927d89b0392c332575d30a73ca0298317d68477c"
            },
            {
                "alert": {
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "index": 0,
                                    "uri": "module1.py",
                                    "uriBaseId": "%SRCROOT%"
                                },
                                "region": {
                                    "endColumn": 49,
                                    "startColumn": 12,
                                    "startLine": 113
                                }
                            }
                        }
                    ],
                    "message": {
                        "text": "Call to [function load_from_config](1) with too many arguments; should be no more than 1."
                    },
                    "partialFingerprints": {
                        "primaryLocationLineHash": "5c8cfaabeac1e16d:1",
                        "primaryLocationStartColumnFingerprint": "7"
                    },
                    "relatedLocations": [
                        {
                            "id": 1,
                            "message": {
                                "text": "function load_from_config"
                            },
                            "physicalLocation": {
                                "artifactLocation": {
                                    "index": 0,
                                    "uri": "module1.py",
                                    "uriBaseId": "%SRCROOT%"
                                },
                                "region": {
                                    "endColumn": 28,
                                    "startLine": 101
                                }
                            }
                        }
                    ],
                    "ruleId": "com.lgtm/python-queries:py/call/wrong-arguments",
                    "ruleIndex": 0
                },
                "analysisId": "927d89b0392c332575d30a73ca0298317d68477c"
            },
            {
                "alert": {
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "index": 0,
                                    "uri": "module1.py",
                                    "uriBaseId": "%SRCROOT%"
                                },
                                "region": {
                                    "endColumn": 19,
                                    "startColumn": 5,
                                    "startLine": 24
                                }
                            }
                        }
                    ],
                    "message": {
                        "text": "This assignment to 'code_execution' is unnecessary as it is redefined [here](1) before this value is used."
                    },
                    "partialFingerprints": {
                        "primaryLocationLineHash": "8180e24b4613f9a2:1",
                        "primaryLocationStartColumnFingerprint": "4"
                    },
                    "relatedLocations": [
                        {
                            "id": 1,
                            "message": {
                                "text": "here"
                            },
                            "physicalLocation": {
                                "artifactLocation": {
                                    "index": 0,
                                    "uri": "module1.py",
                                    "uriBaseId": "%SRCROOT%"
                                },
                                "region": {
                                    "endColumn": 19,
                                    "startColumn": 5,
                                    "startLine": 31
                                }
                            }
                        }
                    ],
                    "ruleId": "com.lgtm/python-queries:py/multiple-definition",
                    "ruleIndex": 1
                },
                "analysisId": "927d89b0392c332575d30a73ca0298317d68477c"
            },
            {
                "alert": {
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "index": 0,
                                    "uri": "module1.py",
                                    "uriBaseId": "%SRCROOT%"
                                },
                                "region": {
                                    "endColumn": 13,
                                    "startColumn": 9,
                                    "startLine": 46
                                }
                            }
                        }
                    ],
                    "message": {
                        "text": "This assignment to 'user' is unnecessary as it is redefined [here](1) before this value is used."
                    },
                    "partialFingerprints": {
                        "primaryLocationLineHash": "5358472308e96529:1",
                        "primaryLocationStartColumnFingerprint": "0"
                    },
                    "relatedLocations": [
                        {
                            "id": 1,
                            "message": {
                                "text": "here"
                            },
                            "physicalLocation": {
                                "artifactLocation": {
                                    "index": 0,
                                    "uri": "module1.py",
                                    "uriBaseId": "%SRCROOT%"
                                },
                                "region": {
                                    "endColumn": 13,
                                    "startColumn": 9,
                                    "startLine": 50
                                }
                            }
                        }
                    ],
                    "ruleId": "com.lgtm/python-queries:py/multiple-definition",
                    "ruleIndex": 1
                },
                "analysisId": "927d89b0392c332575d30a73ca0298317d68477c"
            },
            {
                "alert": {
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "index": 0,
                                    "uri": "module1.py",
                                    "uriBaseId": "%SRCROOT%"
                                },
                                "region": {
                                    "endColumn": 13,
                                    "startColumn": 9,
                                    "startLine": 50
                                }
                            }
                        }
                    ],
                    "message": {
                        "text": "This assignment to 'user' is unnecessary as it is redefined [here](1) before this value is used."
                    },
                    "partialFingerprints": {
                        "primaryLocationLineHash": "1805a8f6fd5b76df:1",
                        "primaryLocationStartColumnFingerprint": "0"
                    },
                    "relatedLocations": [
                        {
                            "id": 1,
                            "message": {
                                "text": "here"
                            },
                            "physicalLocation": {
                                "artifactLocation": {
                                    "index": 0,
                                    "uri": "module1.py",
                                    "uriBaseId": "%SRCROOT%"
                                },
                                "region": {
                                    "endColumn": 13,
                                    "startColumn": 9,
                                    "startLine": 54
                                }
                            }
                        }
                    ],
                    "ruleId": "com.lgtm/python-queries:py/multiple-definition",
                    "ruleIndex": 1
                },
                "analysisId": "927d89b0392c332575d30a73ca0298317d68477c"
            },
            {
                "alert": {
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "index": 0,
                                    "uri": "module1.py",
                                    "uriBaseId": "%SRCROOT%"
                                },
                                "region": {
                                    "endColumn": 19,
                                    "startColumn": 5,
                                    "startLine": 223
                                }
                            }
                        }
                    ],
                    "message": {
                        "text": "This assignment to 'send_encrypted' is unnecessary as it is redefined [here](1) before this value is used."
                    },
                    "partialFingerprints": {
                        "primaryLocationLineHash": "552c6bffbe6cb915:1",
                        "primaryLocationStartColumnFingerprint": "4"
                    },
                    "relatedLocations": [
                        {
                            "id": 1,
                            "message": {
                                "text": "here"
                            },
                            "physicalLocation": {
                                "artifactLocation": {
                                    "index": 0,
                                    "uri": "module1.py",
                                    "uriBaseId": "%SRCROOT%"
                                },
                                "region": {
                                    "endColumn": 19,
                                    "startColumn": 5,
                                    "startLine": 230
                                }
                            }
                        }
                    ],
                    "ruleId": "com.lgtm/python-queries:py/multiple-definition",
                    "ruleIndex": 1
                },
                "analysisId": "927d89b0392c332575d30a73ca0298317d68477c"
            },
            {
                "alert": {
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "index": 0,
                                    "uri": "module1.py",
                                    "uriBaseId": "%SRCROOT%"
                                },
                                "region": {
                                    "endColumn": 13,
                                    "startColumn": 9,
                                    "startLine": 54
                                }
                            }
                        }
                    ],
                    "message": {
                        "text": "The value assigned to local variable 'user' is never used."
                    },
                    "partialFingerprints": {
                        "primaryLocationLineHash": "d37b5c11bd142430:1",
                        "primaryLocationStartColumnFingerprint": "0"
                    },
                    "ruleId": "com.lgtm/python-queries:py/unused-local-variable",
                    "ruleIndex": 2
                },
                "analysisId": "927d89b0392c332575d30a73ca0298317d68477c"
            },
            {
                "alert": {
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "index": 0,
                                    "uri": "module1.py",
                                    "uriBaseId": "%SRCROOT%"
                                },
                                "region": {
                                    "endColumn": 9,
                                    "startColumn": 5,
                                    "startLine": 64
                                }
                            }
                        }
                    ],
                    "message": {
                        "text": "The value assigned to local variable 'data' is never used."
                    },
                    "partialFingerprints": {
                        "primaryLocationLineHash": "b60374c7564cf3b5:1",
                        "primaryLocationStartColumnFingerprint": "0"
                    },
                    "ruleId": "com.lgtm/python-queries:py/unused-local-variable",
                    "ruleIndex": 2
                },
                "analysisId": "927d89b0392c332575d30a73ca0298317d68477c"
            },
            {
                "alert": {
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "index": 0,
                                    "uri": "module1.py",
                                    "uriBaseId": "%SRCROOT%"
                                },
                                "region": {
                                    "endColumn": 9,
                                    "startColumn": 5,
                                    "startLine": 73
                                }
                            }
                        }
                    ],
                    "message": {
                        "text": "The value assigned to local variable 'data' is never used."
                    },
                    "partialFingerprints": {
                        "primaryLocationLineHash": "269b1675deaafb50:1",
                        "primaryLocationStartColumnFingerprint": "0"
                    },
                    "ruleId": "com.lgtm/python-queries:py/unused-local-variable",
                    "ruleIndex": 2
                },
                "analysisId": "927d89b0392c332575d30a73ca0298317d68477c"
            },
            {
                "alert": {
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "index": 0,
                                    "uri": "module1.py",
                                    "uriBaseId": "%SRCROOT%"
                                },
                                "region": {
                                    "endColumn": 9,
                                    "startColumn": 5,
                                    "startLine": 85
                                }
                            }
                        }
                    ],
                    "message": {
                        "text": "The value assigned to local variable 'data' is never used."
                    },
                    "partialFingerprints": {
                        "primaryLocationLineHash": "c32d3d378ff25d1d:1",
                        "primaryLocationStartColumnFingerprint": "0"
                    },
                    "ruleId": "com.lgtm/python-queries:py/unused-local-variable",
                    "ruleIndex": 2
                },
                "analysisId": "927d89b0392c332575d30a73ca0298317d68477c"
            },
            {
                "alert": {
                    "codeFlows": [
                        {
                            "threadFlows": [
                                {
                                    "locations": [
                                        {
                                            "location": {
                                                "message": {
                                                    "text": "Step 1"
                                                },
                                                "physicalLocation": {
                                                    "artifactLocation": {
                                                        "index": 0,
                                                        "uri": "module1.py",
                                                        "uriBaseId": "%SRCROOT%"
                                                    },
                                                    "region": {
                                                        "endColumn": 44,
                                                        "startColumn": 16,
                                                        "startLine": 156
                                                    }
                                                }
                                            }
                                        },
                                        {
                                            "location": {
                                                "message": {
                                                    "text": "Step 2"
                                                },
                                                "physicalLocation": {
                                                    "artifactLocation": {
                                                        "index": 0,
                                                        "uri": "module1.py",
                                                        "uriBaseId": "%SRCROOT%"
                                                    },
                                                    "region": {
                                                        "endColumn": 41,
                                                        "startColumn": 33,
                                                        "startLine": 158
                                                    }
                                                }
                                            }
                                        }
                                    ]
                                }
                            ]
                        }
                    ],
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "index": 0,
                                    "uri": "module1.py",
                                    "uriBaseId": "%SRCROOT%"
                                },
                                "region": {
                                    "endColumn": 41,
                                    "startColumn": 33,
                                    "startLine": 158
                                }
                            }
                        }
                    ],
                    "message": {
                        "text": "Sensitive data from [a request parameter containing a password](1) is stored here."
                    },
                    "partialFingerprints": {
                        "primaryLocationLineHash": "ba844552ea173e36:1",
                        "primaryLocationStartColumnFingerprint": "28"
                    },
                    "relatedLocations": [
                        {
                            "id": 1,
                            "message": {
                                "text": "a request parameter containing a password"
                            },
                            "physicalLocation": {
                                "artifactLocation": {
                                    "index": 0,
                                    "uri": "module1.py",
                                    "uriBaseId": "%SRCROOT%"
                                },
                                "region": {
                                    "endColumn": 44,
                                    "startColumn": 16,
                                    "startLine": 156
                                }
                            }
                        }
                    ],
                    "ruleId": "com.lgtm/python-queries:py/clear-text-storage-sensitive-data",
                    "ruleIndex": 3
                },
                "analysisId": "927d89b0392c332575d30a73ca0298317d68477c"
            }
        ]
    }
}
```

#### Human Readable Output

>### LGTM - Code Analysis Alerts
>|alert|analysisId|
>|---|---|
>| ruleId: com.lgtm/python-queries:py/call/wrong-arguments<br/>ruleIndex: 0<br/>message: {"text": "Call to [function load_from_config](1) with too many arguments; should be no more than 1."}<br/>locations: {'physicalLocation': {'artifactLocation': {'uri': 'module1.py', 'uriBaseId': '%SRCROOT%', 'index': 0}, 'region': {'startLine': 112, 'startColumn': 23, 'endColumn': 70}}}<br/>partialFingerprints: {"primaryLocationLineHash": "a8e1daf8b5008d1d:1", "primaryLocationStartColumnFingerprint": "18"}<br/>relatedLocations: {'id': 1, 'physicalLocation': {'artifactLocation': {'uri': 'module1.py', 'uriBaseId': '%SRCROOT%', 'index': 0}, 'region': {'startLine': 101, 'endColumn': 28}}, 'message': {'text': 'function load_from_config'}} | 927d89b0392c332575d30a73ca0298317d68477c |
>| ruleId: com.lgtm/python-queries:py/call/wrong-arguments<br/>ruleIndex: 0<br/>message: {"text": "Call to [function load_from_config](1) with too many arguments; should be no more than 1."}<br/>locations: {'physicalLocation': {'artifactLocation': {'uri': 'module1.py', 'uriBaseId': '%SRCROOT%', 'index': 0}, 'region': {'startLine': 113, 'startColumn': 12, 'endColumn': 49}}}<br/>partialFingerprints: {"primaryLocationLineHash": "5c8cfaabeac1e16d:1", "primaryLocationStartColumnFingerprint": "7"}<br/>relatedLocations: {'id': 1, 'physicalLocation': {'artifactLocation': {'uri': 'module1.py', 'uriBaseId': '%SRCROOT%', 'index': 0}, 'region': {'startLine': 101, 'endColumn': 28}}, 'message': {'text': 'function load_from_config'}} | 927d89b0392c332575d30a73ca0298317d68477c |
>| ruleId: com.lgtm/python-queries:py/multiple-definition<br/>ruleIndex: 1<br/>message: {"text": "This assignment to 'code_execution' is unnecessary as it is redefined [here](1) before this value is used."}<br/>locations: {'physicalLocation': {'artifactLocation': {'uri': 'module1.py', 'uriBaseId': '%SRCROOT%', 'index': 0}, 'region': {'startLine': 24, 'startColumn': 5, 'endColumn': 19}}}<br/>partialFingerprints: {"primaryLocationLineHash": "8180e24b4613f9a2:1", "primaryLocationStartColumnFingerprint": "4"}<br/>relatedLocations: {'id': 1, 'physicalLocation': {'artifactLocation': {'uri': 'module1.py', 'uriBaseId': '%SRCROOT%', 'index': 0}, 'region': {'startLine': 31, 'startColumn': 5, 'endColumn': 19}}, 'message': {'text': 'here'}} | 927d89b0392c332575d30a73ca0298317d68477c |
>| ruleId: com.lgtm/python-queries:py/multiple-definition<br/>ruleIndex: 1<br/>message: {"text": "This assignment to 'user' is unnecessary as it is redefined [here](1) before this value is used."}<br/>locations: {'physicalLocation': {'artifactLocation': {'uri': 'module1.py', 'uriBaseId': '%SRCROOT%', 'index': 0}, 'region': {'startLine': 46, 'startColumn': 9, 'endColumn': 13}}}<br/>partialFingerprints: {"primaryLocationLineHash": "5358472308e96529:1", "primaryLocationStartColumnFingerprint": "0"}<br/>relatedLocations: {'id': 1, 'physicalLocation': {'artifactLocation': {'uri': 'module1.py', 'uriBaseId': '%SRCROOT%', 'index': 0}, 'region': {'startLine': 50, 'startColumn': 9, 'endColumn': 13}}, 'message': {'text': 'here'}} | 927d89b0392c332575d30a73ca0298317d68477c |
>| ruleId: com.lgtm/python-queries:py/multiple-definition<br/>ruleIndex: 1<br/>message: {"text": "This assignment to 'user' is unnecessary as it is redefined [here](1) before this value is used."}<br/>locations: {'physicalLocation': {'artifactLocation': {'uri': 'module1.py', 'uriBaseId': '%SRCROOT%', 'index': 0}, 'region': {'startLine': 50, 'startColumn': 9, 'endColumn': 13}}}<br/>partialFingerprints: {"primaryLocationLineHash": "1805a8f6fd5b76df:1", "primaryLocationStartColumnFingerprint": "0"}<br/>relatedLocations: {'id': 1, 'physicalLocation': {'artifactLocation': {'uri': 'module1.py', 'uriBaseId': '%SRCROOT%', 'index': 0}, 'region': {'startLine': 54, 'startColumn': 9, 'endColumn': 13}}, 'message': {'text': 'here'}} | 927d89b0392c332575d30a73ca0298317d68477c |
>| ruleId: com.lgtm/python-queries:py/multiple-definition<br/>ruleIndex: 1<br/>message: {"text": "This assignment to 'send_encrypted' is unnecessary as it is redefined [here](1) before this value is used."}<br/>locations: {'physicalLocation': {'artifactLocation': {'uri': 'module1.py', 'uriBaseId': '%SRCROOT%', 'index': 0}, 'region': {'startLine': 223, 'startColumn': 5, 'endColumn': 19}}}<br/>partialFingerprints: {"primaryLocationLineHash": "552c6bffbe6cb915:1", "primaryLocationStartColumnFingerprint": "4"}<br/>relatedLocations: {'id': 1, 'physicalLocation': {'artifactLocation': {'uri': 'module1.py', 'uriBaseId': '%SRCROOT%', 'index': 0}, 'region': {'startLine': 230, 'startColumn': 5, 'endColumn': 19}}, 'message': {'text': 'here'}} | 927d89b0392c332575d30a73ca0298317d68477c |
>| ruleId: com.lgtm/python-queries:py/unused-local-variable<br/>ruleIndex: 2<br/>message: {"text": "The value assigned to local variable 'user' is never used."}<br/>locations: {'physicalLocation': {'artifactLocation': {'uri': 'module1.py', 'uriBaseId': '%SRCROOT%', 'index': 0}, 'region': {'startLine': 54, 'startColumn': 9, 'endColumn': 13}}}<br/>partialFingerprints: {"primaryLocationLineHash": "d37b5c11bd142430:1", "primaryLocationStartColumnFingerprint": "0"} | 927d89b0392c332575d30a73ca0298317d68477c |
>| ruleId: com.lgtm/python-queries:py/unused-local-variable<br/>ruleIndex: 2<br/>message: {"text": "The value assigned to local variable 'data' is never used."}<br/>locations: {'physicalLocation': {'artifactLocation': {'uri': 'module1.py', 'uriBaseId': '%SRCROOT%', 'index': 0}, 'region': {'startLine': 64, 'startColumn': 5, 'endColumn': 9}}}<br/>partialFingerprints: {"primaryLocationLineHash": "b60374c7564cf3b5:1", "primaryLocationStartColumnFingerprint": "0"} | 927d89b0392c332575d30a73ca0298317d68477c |
>| ruleId: com.lgtm/python-queries:py/unused-local-variable<br/>ruleIndex: 2<br/>message: {"text": "The value assigned to local variable 'data' is never used."}<br/>locations: {'physicalLocation': {'artifactLocation': {'uri': 'module1.py', 'uriBaseId': '%SRCROOT%', 'index': 0}, 'region': {'startLine': 73, 'startColumn': 5, 'endColumn': 9}}}<br/>partialFingerprints: {"primaryLocationLineHash": "269b1675deaafb50:1", "primaryLocationStartColumnFingerprint": "0"} | 927d89b0392c332575d30a73ca0298317d68477c |
>| ruleId: com.lgtm/python-queries:py/unused-local-variable<br/>ruleIndex: 2<br/>message: {"text": "The value assigned to local variable 'data' is never used."}<br/>locations: {'physicalLocation': {'artifactLocation': {'uri': 'module1.py', 'uriBaseId': '%SRCROOT%', 'index': 0}, 'region': {'startLine': 85, 'startColumn': 5, 'endColumn': 9}}}<br/>partialFingerprints: {"primaryLocationLineHash": "c32d3d378ff25d1d:1", "primaryLocationStartColumnFingerprint": "0"} | 927d89b0392c332575d30a73ca0298317d68477c |
>| ruleId: com.lgtm/python-queries:py/clear-text-storage-sensitive-data<br/>ruleIndex: 3<br/>message: {"text": "Sensitive data from [a request parameter containing a password](1) is stored here."}<br/>locations: {'physicalLocation': {'artifactLocation': {'uri': 'module1.py', 'uriBaseId': '%SRCROOT%', 'index': 0}, 'region': {'startLine': 158, 'startColumn': 33, 'endColumn': 41}}}<br/>partialFingerprints: {"primaryLocationLineHash": "ba844552ea173e36:1", "primaryLocationStartColumnFingerprint": "28"}<br/>codeFlows: {'threadFlows': [{'locations': [{'location': {'physicalLocation': {'artifactLocation': {'uri': 'module1.py', 'uriBaseId': '%SRCROOT%', 'index': 0}, 'region': {'startLine': 156, 'startColumn': 16, 'endColumn': 44}}, 'message': {'text': 'Step 1'}}}, {'location': {'physicalLocation': {'artifactLocation': {'uri': 'module1.py', 'uriBaseId': '%SRCROOT%', 'index': 0}, 'region': {'startLine': 158, 'startColumn': 33, 'endColumn': 41}}, 'message': {'text': 'Step 2'}}}]}]}<br/>relatedLocations: {'id': 1, 'physicalLocation': {'artifactLocation': {'uri': 'module1.py', 'uriBaseId': '%SRCROOT%', 'index': 0}, 'region': {'startLine': 156, 'startColumn': 16, 'endColumn': 44}}, 'message': {'text': 'a request parameter containing a password'}} | 927d89b0392c332575d30a73ca0298317d68477c |

