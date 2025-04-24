An Integration with LGTM API
This integration was integrated and tested with version 1.0 of LGTM
## Configure LGTM in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server URL (e.g. `https://lgtm.com/api/v1.0`) | True |
| api_key | API Key | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### lgtm-add-project
***
Add a project to LGTM


#### Base Command

`lgtm-add-project`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| repository | The URL of the repository to analyze. LGTM tests this against the [repository providers](https://lgtm.com/admin/help/adding-repository-providers) defined for the system. If it doesn't match any of them, the request fails. | Required | 
| language | Optional, a [language code](https://lgtm.com/help/lgtm/analysis-faqs#which-languages-are-supported) to specify which language to analyze. To request the analysis of more than one language, specify a query  meter for each language. By default, LGTM tries to analyze all supported languages.  | Optional | 
| mode | The analysis mode of the new project. When set to `full` all commits of the project are analyzed; when set to `sparse` the latest commit of the project is analyzed periodically; when set to `upload`,  no automatic analysis is performed, instead externally-generated databases should be uploaded. For new projects the default value is `full`. The `mode`  meter cannot be used to change the analysis mode of existing projects. Therefore, for existing projects, it should either be left blank or set to match the analysis mode of the project.  | Optional | 
| commit | Required when `mode=upload`, specify the identifier of the commit used to generate the database. | Optional | 
| date | Optional when `mode=upload`, specify the date and time of the commit used to generate the database; defaults to the current time. | Optional | 
| worker-label | Optional, any [labels](https://lgtm.com/admin/help/defining-worker-labels) required by workers to analyze this project.  To specify more than one label, repeat the query  meter.  | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### lgtm-get-alerts
***
Get detailed alert information


#### Base Command

`lgtm-get-alerts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| analysis-id | The analysis identifier. | Required | 
| sarif-version | The desired version of the SARIF format. Currently supported versions are `1.0.0`, `2.0.0`, and `2.1.0`. | Optional | 
| excluded-files | Set `true` to include results in files that are excluded from the output by default. This includes results in test code and generated files. For more information, see [File classification](https://lgtm.com/help/lgtm/file-classification). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LGTM.alerts.runs.results.ruleId | Unknown | LGTM Alerts by Rule ID | 
| LGTM.alerts.runs.results.partialFingerprints.primaryLocationLineHash | Unknown | LGTM Alert location by line hash | 


#### Command Example
```!lgtm-get-alerts analysis-id=1977acc9cbeb31c5fb106de40600a365061506e9```

#### Context Example
```json
{
    "LGTM": {
        "alerts": {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [
                {
                    "artifacts": [
                        {
                            "location": {
                                "index": 0,
                                "uri": "module1.py",
                                "uriBaseId": "%SRCROOT%"
                            }
                        }
                    ],
                    "columnKind": "unicodeCodePoints",
                    "properties": {
                        "semmle.formatSpecifier": "2.1.0",
                        "semmle.sourceLanguage": "python"
                    },
                    "results": [
                        {
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
                        {
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
                        {
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
                        {
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
                        {
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
                        {
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
                        {
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
                        {
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
                        {
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
                        {
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
                        {
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
                        }
                    ],
                    "tool": {
                        "driver": {
                            "name": "LGTM.com",
                            "organization": "Semmle",
                            "rules": [
                                {
                                    "defaultConfiguration": {
                                        "level": "error"
                                    },
                                    "fullDescription": {
                                        "text": "Using too many or too few arguments in a call to a function will result in a TypeError at runtime."
                                    },
                                    "id": "com.lgtm/python-queries:py/call/wrong-arguments",
                                    "name": "com.lgtm/python-queries:py/call/wrong-arguments",
                                    "properties": {
                                        "kind": "problem",
                                        "precision": "very-high",
                                        "problem.severity": "error",
                                        "sub-severity": "low",
                                        "tags": [
                                            "reliability",
                                            "correctness",
                                            "external/cwe/cwe-685"
                                        ]
                                    },
                                    "shortDescription": {
                                        "text": "Wrong number of arguments in a call"
                                    }
                                },
                                {
                                    "defaultConfiguration": {},
                                    "fullDescription": {
                                        "text": "Assignment to a variable occurs multiple times without any intermediate use of that variable"
                                    },
                                    "id": "com.lgtm/python-queries:py/multiple-definition",
                                    "name": "com.lgtm/python-queries:py/multiple-definition",
                                    "properties": {
                                        "kind": "problem",
                                        "precision": "very-high",
                                        "problem.severity": "warning",
                                        "sub-severity": "low",
                                        "tags": [
                                            "maintainability",
                                            "useless-code",
                                            "external/cwe/cwe-563"
                                        ]
                                    },
                                    "shortDescription": {
                                        "text": "Variable defined multiple times"
                                    }
                                },
                                {
                                    "defaultConfiguration": {
                                        "level": "note"
                                    },
                                    "fullDescription": {
                                        "text": "Local variable is defined but not used"
                                    },
                                    "id": "com.lgtm/python-queries:py/unused-local-variable",
                                    "name": "com.lgtm/python-queries:py/unused-local-variable",
                                    "properties": {
                                        "kind": "problem",
                                        "precision": "very-high",
                                        "problem.severity": "recommendation",
                                        "sub-severity": "high",
                                        "tags": [
                                            "maintainability",
                                            "useless-code",
                                            "external/cwe/cwe-563"
                                        ]
                                    },
                                    "shortDescription": {
                                        "text": "Unused local variable"
                                    }
                                },
                                {
                                    "defaultConfiguration": {
                                        "level": "error"
                                    },
                                    "fullDescription": {
                                        "text": "Sensitive information stored without encryption or hashing can expose it to an attacker."
                                    },
                                    "id": "com.lgtm/python-queries:py/clear-text-storage-sensitive-data",
                                    "name": "com.lgtm/python-queries:py/clear-text-storage-sensitive-data",
                                    "properties": {
                                        "kind": "path-problem",
                                        "precision": "high",
                                        "problem.severity": "error",
                                        "tags": [
                                            "security",
                                            "external/cwe/cwe-312",
                                            "external/cwe/cwe-315",
                                            "external/cwe/cwe-359"
                                        ]
                                    },
                                    "shortDescription": {
                                        "text": "Clear-text storage of sensitive information"
                                    }
                                }
                            ],
                            "version": "1.26.0-SNAPSHOT"
                        }
                    }
                }
            ],
            "version": "2.1.0"
        }
    }
}
```

#### Human Readable Output

>### Results
>|$schema|runs|version|
>|---|---|---|
>| https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json | {'tool': {'driver': {'name': 'LGTM.com', 'organization': 'Semmle', 'version': '1.26.0-SNAPSHOT', 'rules': [{'id': 'com.lgtm/python-queries:py/call/wrong-arguments', 'name': 'com.lgtm/python-queries:py/call/wrong-arguments', 'shortDescription': {'text': 'Wrong number of arguments in a call'}, 'fullDescription': {'text': 'Using too many or too few arguments in a call to a function will result in a TypeError at runtime.'}, 'defaultConfiguration': {'level': 'error'}, 'properties': {'tags': ['reliability', 'correctness', 'external/cwe/cwe-685'], 'kind': 'problem', 'precision': 'very-high', 'sub-severity': 'low', 'problem.severity': 'error'}}, {'id': 'com.lgtm/python-queries:py/multiple-definition', 'name': 'com.lgtm/python-queries:py/multiple-definition', 'shortDescription': {'text': 'Variable defined multiple times'}, 'fullDescription': {'text': 'Assignment to a variable occurs multiple times without any intermediate use of that variable'}, 'defaultConfiguration': {}, 'properties': {'tags': ['maintainability', 'useless-code', 'external/cwe/cwe-563'], 'kind': 'problem', 'precision': 'very-high', 'sub-severity': 'low', 'problem.severity': 'warning'}}, {'id': 'com.lgtm/python-queries:py/unused-local-variable', 'name': 'com.lgtm/python-queries:py/unused-local-variable', 'shortDescription': {'text': 'Unused local variable'}, 'fullDescription': {'text': 'Local variable is defined but not used'}, 'defaultConfiguration': {'level': 'note'}, 'properties': {'tags': ['maintainability', 'useless-code', 'external/cwe/cwe-563'], 'kind': 'problem', 'precision': 'very-high', 'sub-severity': 'high', 'problem.severity': 'recommendation'}}, {'id': 'com.lgtm/python-queries:py/clear-text-storage-sensitive-data', 'name': 'com.lgtm/python-queries:py/clear-text-storage-sensitive-data', 'shortDescription': {'text': 'Clear-text storage of sensitive information'}, 'fullDescription': {'text': 'Sensitive information stored without encryption or hashing can expose it to an attacker.'}, 'defaultConfiguration': {'level': 'error'}, 'properties': {'tags': ['security', 'external/cwe/cwe-312', 'external/cwe/cwe-315', 'external/cwe/cwe-359'], 'kind': 'path-problem', 'precision': 'high', 'problem.severity': 'error'}}]}}, 'artifacts': [{'location': {'uri': 'module1.py', 'uriBaseId': '%SRCROOT%', 'index': 0}}], 'results': [{'ruleId': 'com.lgtm/python-queries:py/call/wrong-arguments', 'ruleIndex': 0, 'message': {'text': 'Call to `[function load_from_config](1)` with too many arguments; should be no more than 1.'}, 'locations': [{'physicalLocation': {'artifactLocation': {'uri': 'module1.py', 'uriBaseId': '%SRCROOT%', 'index': 0}, 'region': {'startLine': 112, 'startColumn': 23, 'endColumn': 70}}}], 'partialFingerprints': {'primaryLocationLineHash': 'a8e1daf8b5008d1d:1', 'primaryLocationStartColumnFingerprint': '18'}, 'relatedLocations': [{'id': 1, 'physicalLocation': {'artifactLocation': {'uri': 'module1.py', 'uriBaseId': '%SRCROOT%', 'index': 0}, 'region': {'startLine': 101, 'endColumn': 28}}, 'message': {'text': 'function load_from_config'}}]}, {'ruleId': 'com.lgtm/python-queries:py/call/wrong-arguments', 'ruleIndex': 0, 'message': {'text': 'Call to `[function load_from_config](1)` with too many arguments; should be no more than 1.'}, 'locations': [{'physicalLocation': {'artifactLocation': {'uri': 'module1.py', 'uriBaseId': '%SRCROOT%', 'index': 0}, 'region': {'startLine': 113, 'startColumn': 12, 'endColumn': 49}}}], 'partialFingerprints': {'primaryLocationLineHash': '5c8cfaabeac1e16d:1', 'primaryLocationStartColumnFingerprint': '7'}, 'relatedLocations': [{'id': 1, 'physicalLocation': {'artifactLocation': {'uri': 'module1.py', 'uriBaseId': '%SRCROOT%', 'index': 0}, 'region': {'startLine': 101, 'endColumn': 28}}, 'message': {'text': 'function load_from_config'}}]}, {'ruleId': 'com.lgtm/python-queries:py/multiple-definition', 'ruleIndex': 1, 'message': {'text': "This assignment to 'code_execution' is unnecessary as it is redefined `[here](1)` before this value is used."}, 'locations': [{'physicalLocation': {'artifactLocation': {'uri': 'module1.py', 'uriBaseId': '%SRCROOT%', 'index': 0}, 'region': {'startLine': 24, 'startColumn': 5, 'endColumn': 19}}}], 'partialFingerprints': {'primaryLocationLineHash': '8180e24b4613f9a2:1', 'primaryLocationStartColumnFingerprint': '4'}, 'relatedLocations': [{'id': 1, 'physicalLocation': {'artifactLocation': {'uri': 'module1.py', 'uriBaseId': '%SRCROOT%', 'index': 0}, 'region': {'startLine': 31, 'startColumn': 5, 'endColumn': 19}}, 'message': {'text': 'here'}}]}, {'ruleId': 'com.lgtm/python-queries:py/multiple-definition', 'ruleIndex': 1, 'message': {'text': "This assignment to 'user' is unnecessary as it is redefined `[here](1)` before this value is used."}, 'locations': [{'physicalLocation': {'artifactLocation': {'uri': 'module1.py', 'uriBaseId': '%SRCROOT%', 'index': 0}, 'region': {'startLine': 46, 'startColumn': 9, 'endColumn': 13}}}], 'partialFingerprints': {'primaryLocationLineHash': '5358472308e96529:1', 'primaryLocationStartColumnFingerprint': '0'}, 'relatedLocations': [{'id': 1, 'physicalLocation': {'artifactLocation': {'uri': 'module1.py', 'uriBaseId': '%SRCROOT%', 'index': 0}, 'region': {'startLine': 50, 'startColumn': 9, 'endColumn': 13}}, 'message': {'text': 'here'}}]}, {'ruleId': 'com.lgtm/python-queries:py/multiple-definition', 'ruleIndex': 1, 'message': {'text': "This assignment to 'user' is unnecessary as it is redefined `[here](1)` before this value is used."}, 'locations': [{'physicalLocation': {'artifactLocation': {'uri': 'module1.py', 'uriBaseId': '%SRCROOT%', 'index': 0}, 'region': {'startLine': 50, 'startColumn': 9, 'endColumn': 13}}}], 'partialFingerprints': {'primaryLocationLineHash': '1805a8f6fd5b76df:1', 'primaryLocationStartColumnFingerprint': '0'}, 'relatedLocations': [{'id': 1, 'physicalLocation': {'artifactLocation': {'uri': 'module1.py', 'uriBaseId': '%SRCROOT%', 'index': 0}, 'region': {'startLine': 54, 'startColumn': 9, 'endColumn': 13}}, 'message': {'text': 'here'}}]}, {'ruleId': 'com.lgtm/python-queries:py/multiple-definition', 'ruleIndex': 1, 'message': {'text': "This assignment to 'send_encrypted' is unnecessary as it is redefined `[here](1)` before this value is used."}, 'locations': [{'physicalLocation': {'artifactLocation': {'uri': 'module1.py', 'uriBaseId': '%SRCROOT%', 'index': 0}, 'region': {'startLine': 223, 'startColumn': 5, 'endColumn': 19}}}], 'partialFingerprints': {'primaryLocationLineHash': '552c6bffbe6cb915:1', 'primaryLocationStartColumnFingerprint': '4'}, 'relatedLocations': [{'id': 1, 'physicalLocation': {'artifactLocation': {'uri': 'module1.py', 'uriBaseId': '%SRCROOT%', 'index': 0}, 'region': {'startLine': 230, 'startColumn': 5, 'endColumn': 19}}, 'message': {'text': 'here'}}]}, {'ruleId': 'com.lgtm/python-queries:py/unused-local-variable', 'ruleIndex': 2, 'message': {'text': "The value assigned to local variable 'user' is never used."}, 'locations': [{'physicalLocation': {'artifactLocation': {'uri': 'module1.py', 'uriBaseId': '%SRCROOT%', 'index': 0}, 'region': {'startLine': 54, 'startColumn': 9, 'endColumn': 13}}}], 'partialFingerprints': {'primaryLocationLineHash': 'd37b5c11bd142430:1', 'primaryLocationStartColumnFingerprint': '0'}}, {'ruleId': 'com.lgtm/python-queries:py/unused-local-variable', 'ruleIndex': 2, 'message': {'text': "The value assigned to local variable 'data' is never used."}, 'locations': [{'physicalLocation': {'artifactLocation': {'uri': 'module1.py', 'uriBaseId': '%SRCROOT%', 'index': 0}, 'region': {'startLine': 64, 'startColumn': 5, 'endColumn': 9}}}], 'partialFingerprints': {'primaryLocationLineHash': 'b60374c7564cf3b5:1', 'primaryLocationStartColumnFingerprint': '0'}}, {'ruleId': 'com.lgtm/python-queries:py/unused-local-variable', 'ruleIndex': 2, 'message': {'text': "The value assigned to local variable 'data' is never used."}, 'locations': [{'physicalLocation': {'artifactLocation': {'uri': 'module1.py', 'uriBaseId': '%SRCROOT%', 'index': 0}, 'region': {'startLine': 73, 'startColumn': 5, 'endColumn': 9}}}], 'partialFingerprints': {'primaryLocationLineHash': '269b1675deaafb50:1', 'primaryLocationStartColumnFingerprint': '0'}}, {'ruleId': 'com.lgtm/python-queries:py/unused-local-variable', 'ruleIndex': 2, 'message': {'text': "The value assigned to local variable 'data' is never used."}, 'locations': [{'physicalLocation': {'artifactLocation': {'uri': 'module1.py', 'uriBaseId': '%SRCROOT%', 'index': 0}, 'region': {'startLine': 85, 'startColumn': 5, 'endColumn': 9}}}], 'partialFingerprints': {'primaryLocationLineHash': 'c32d3d378ff25d1d:1', 'primaryLocationStartColumnFingerprint': '0'}}, {'ruleId': 'com.lgtm/python-queries:py/clear-text-storage-sensitive-data', 'ruleIndex': 3, 'message': {'text': 'Sensitive data from `[a request parameter containing a password](1)` is stored here.'}, 'locations': [{'physicalLocation': {'artifactLocation': {'uri': 'module1.py', 'uriBaseId': '%SRCROOT%', 'index': 0}, 'region': {'startLine': 158, 'startColumn': 33, 'endColumn': 41}}}], 'partialFingerprints': {'primaryLocationLineHash': 'ba844552ea173e36:1', 'primaryLocationStartColumnFingerprint': '28'}, 'codeFlows': [{'threadFlows': [{'locations': [{'location': {'physicalLocation': {'artifactLocation': {'uri': 'module1.py', 'uriBaseId': '%SRCROOT%', 'index': 0}, 'region': {'startLine': 156, 'startColumn': 16, 'endColumn': 44}}, 'message': {'text': 'Step 1'}}}, {'location': {'physicalLocation': {'artifactLocation': {'uri': 'module1.py', 'uriBaseId': '%SRCROOT%', 'index': 0}, 'region': {'startLine': 158, 'startColumn': 33, 'endColumn': 41}}, 'message': {'text': 'Step 2'}}}]}]}], 'relatedLocations': [{'id': 1, 'physicalLocation': {'artifactLocation': {'uri': 'module1.py', 'uriBaseId': '%SRCROOT%', 'index': 0}, 'region': {'startLine': 156, 'startColumn': 16, 'endColumn': 44}}, 'message': {'text': 'a request parameter containing a password'}}]}], 'columnKind': 'unicodeCodePoints', 'properties': {'semmle.formatSpecifier': '2.1.0', 'semmle.sourceLanguage': 'python'}} | 2.1.0 |


### lgtm-get-analysis
***
Get analysis summary


#### Base Command

`lgtm-get-analysis`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| analysis-id | The analysis identifier. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LGTM.analysis_summary.id | String | The analysis identifier. | 
| LGTM.analysis_summary.commit-id | String | The commit identifier. The commit identifier is included only if the same commit was successfully analyzed for all languages. A detailed  eakdown of which commit was analyzed for each language is provided in the \`languages\` property.  | 
| LGTM.analysis_summary.languages.language | String | The short name for the language. | 
| LGTM.analysis_summary.languages.status | String | The status of the analysis of this language. | 
| LGTM.analysis_summary.languages.alerts | Number | The number of alerts for this language. | 
| LGTM.analysis_summary.languages.lines | Number | The number of lines of code for this language. | 
| LGTM.analysis_summary.languages.commit-id | String | The latest successfully analyzed commit for the language. All statistics refer to this commit. | 
| LGTM.analysis_summary.languages.commit-date | String | The time of the commit. | 
| LGTM.analysis_summary.languages.analysis-date | String | The time the commit was analyzed. | 
| LGTM.analysis_summary.log-url | String | A page on LGTM to view the logs for this analysis. | 
| LGTM.analysis_summary.results-url | String | A page on LGTM to view the results of this analysis. | 


#### Command Example
```!lgtm-get-analysis analysis-id=c8996fdd9968066cd410eda9deffdfdcca550e14```

#### Context Example
```json
{
    "LGTM": {
        "analysis_summary": {
            "commit-id": "b1b136e071533d78053be506d32f79417651727d",
            "id": "c8996fdd9968066cd410eda9deffdfdcca550e14",
            "languages": [
                {
                    "alerts": 5,
                    "analysis-date": "2020-06-03T10:09:59.802+0000",
                    "commit-id": "b1b136e071533d78053be506d32f79417651727d",
                    "language": "python",
                    "lines": 87,
                    "status": "success"
                }
            ],
            "log-url": "https://lgtm.com/projects/g/my-tradingbot/scanner/logs/analysis/c8996fdd9968066cd410eda9deffdfdcca550e14",
            "project": {
                "id": 1511925128331,
                "name": "my-tradingbot/scanner",
                "url": "https://lgtm.com/projects/g/my-tradingbot/scanner",
                "url-identifier": "g/my-tradingbot/scanner"
            },
            "results-url": "https://lgtm.com/projects/g/my-tradingbot/scanner/analysis/c8996fdd9968066cd410eda9deffdfdcca550e14/files"
        }
    }
}
```

#### Human Readable Output

>### Results
>|commit-id|id|languages|log-url|project|results-url|
>|---|---|---|---|---|---|
>| b1b136e071533d78053be506d32f79417651727d | c8996fdd9968066cd410eda9deffdfdcca550e14 | {'language': 'python', 'status': 'success', 'alerts': 5, 'lines': 87, 'commit-id': 'b1b136e071533d78053be506d32f79417651727d', 'analysis-date': '2020-06-03T10:09:59.802+0000'} | https://lgtm.com/projects/g/my-tradingbot/scanner/logs/analysis/c8996fdd9968066cd410eda9deffdfdcca550e14 | id: 1511925128331<br/>url-identifier: g/my-tradingbot/scanner<br/>name: my-tradingbot/scanner<br/>url: https://lgtm.com/projects/g/my-tradingbot/scanner | https://lgtm.com/projects/g/my-tradingbot/scanner/analysis/c8996fdd9968066cd410eda9deffdfdcca550e14/files |


### lgtm-get-analysis-for-commit
***
Get analysis summary for a specific commit


#### Base Command

`lgtm-get-analysis-for-commit`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project-id | The numeric project identifier. | Required | 
| commit-id | The identifier of a specific commit. Alternatively, use `latest` for the most recent analyzed commit. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LGTM.analysis_summary.id | String | The analysis identifier. | 
| LGTM.analysis_summary.commit-id | String | The commit identifier. The commit identifier is included only if the same commit was successfully analyzed for all languages. A detailed  eakdown of which commit was analyzed for each language is provided in the \`languages\` property.  | 
| LGTM.analysis_summary.languages.language | String | The short name for the language. | 
| LGTM.analysis_summary.languages.status | String | The status of the analysis of this language. | 
| LGTM.analysis_summary.languages.alerts | Number | The number of alerts for this language. | 
| LGTM.analysis_summary.languages.lines | Number | The number of lines of code for this language. | 
| LGTM.analysis_summary.languages.commit-id | String | The latest successfully analyzed commit for the language. All statistics refer to this commit. | 
| LGTM.analysis_summary.languages.commit-date | String | The time of the commit. | 
| LGTM.analysis_summary.languages.analysis-date | String | The time the commit was analyzed. | 
| LGTM.analysis_summary.log-url | String | A page on LGTM to view the logs for this analysis. | 
| LGTM.analysis_summary.results-url | String | A page on LGTM to view the results of this analysis. | 


#### Command Example
```!lgtm-get-analysis-for-commit commit-id=b1b136e071533d78053be506d32f79417651727d project-id=1511925128331```

#### Context Example
```json
{
    "LGTM": {
        "analysis_summary": {
            "commit-id": "b1b136e071533d78053be506d32f79417651727d",
            "id": "c8996fdd9968066cd410eda9deffdfdcca550e14",
            "languages": [
                {
                    "alerts": 5,
                    "analysis-date": "2020-06-03T10:09:59.802+0000",
                    "commit-id": "b1b136e071533d78053be506d32f79417651727d",
                    "language": "python",
                    "lines": 87,
                    "status": "success"
                }
            ],
            "log-url": "https://lgtm.com/projects/g/my-tradingbot/scanner/logs/analysis/c8996fdd9968066cd410eda9deffdfdcca550e14",
            "project": {
                "id": 1511925128331,
                "name": "my-tradingbot/scanner",
                "url": "https://lgtm.com/projects/g/my-tradingbot/scanner",
                "url-identifier": "g/my-tradingbot/scanner"
            },
            "results-url": "https://lgtm.com/projects/g/my-tradingbot/scanner/analysis/c8996fdd9968066cd410eda9deffdfdcca550e14/files"
        }
    }
}
```

#### Human Readable Output

>### Results
>|commit-id|id|languages|log-url|project|results-url|
>|---|---|---|---|---|---|
>| b1b136e071533d78053be506d32f79417651727d | c8996fdd9968066cd410eda9deffdfdcca550e14 | {'language': 'python', 'status': 'success', 'alerts': 5, 'lines': 87, 'commit-id': 'b1b136e071533d78053be506d32f79417651727d', 'analysis-date': '2020-06-03T10:09:59.802+0000'} | https://lgtm.com/projects/g/my-tradingbot/scanner/logs/analysis/c8996fdd9968066cd410eda9deffdfdcca550e14 | id: 1511925128331<br/>url-identifier: g/my-tradingbot/scanner<br/>name: my-tradingbot/scanner<br/>url: https://lgtm.com/projects/g/my-tradingbot/scanner | https://lgtm.com/projects/g/my-tradingbot/scanner/analysis/c8996fdd9968066cd410eda9deffdfdcca550e14/files |


### lgtm-get-code-review
***
Get results of code review


#### Base Command

`lgtm-get-code-review`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| review-id | The identifier for the review (from the `task-result-url`). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LGTM.code_review_result.id | String | The identifier for the review. | 
| LGTM.code_review_result.results-url | String | A page on LGTM to view the status and results of this code review. | 
| LGTM.code_review_result.status | String | The status of the code review. | 
| LGTM.code_review_result.status-message | String | A summary of the current status of the code review. | 
| LGTM.code_review_result.languages.language | String | The language analyzed. | 
| LGTM.code_review_result.languages.status | String | The status for analysis of this language. | 
| LGTM.code_review_result.languages.status-message | String | The current state of analysis of this langauge. When available, a summary of analysis results. | 
| LGTM.code_review_result.languages.new | Number | The total number of alerts introduced by the patch for this language. | 
| LGTM.code_review_result.languages.fixed | Number | The total number of alerts fixed by the patch for this language. | 
| LGTM.code_review_result.languages.alerts.new | Number | The number of alerts introduced by the patch for this query. | 
| LGTM.code_review_result.languages.alerts.fixed | Number | The number of alerts fixed by the patch for this query. | 


#### Command Example
```!lgtm-get-code-review review-id=525d2cd0df76e6ba1e5a47c920b61cacb8e4068e```

#### Context Example
```json
{
    "LGTM": {
        "code_review_result": {
            "id": "525d2cd0df76e6ba1e5a47c920b61cacb8e4068e",
            "languages": [
                {
                    "alerts": [
                        {
                            "fixed": 0,
                            "new": 0,
                            "query": {
                                "id": 9980089,
                                "language": "python",
                                "name": "Statement has no effect",
                                "pack": "com.lgtm/python-queries",
                                "properties": {
                                    "id": "py/ineffectual-statement",
                                    "name": "Statement has no effect",
                                    "severity": "recommendation",
                                    "tags": [
                                        "maintainability",
                                        "useless-code",
                                        "external/cwe/cwe-561"
                                    ]
                                },
                                "url": "https://lgtm.com/rules/9980089"
                            }
                        },
                        {
                            "fixed": 1,
                            "new": 0,
                            "query": {
                                "id": 1510006386081,
                                "language": "python",
                                "name": "Clear-text storage of sensitive information",
                                "pack": "com.lgtm/python-queries",
                                "properties": {
                                    "id": "py/clear-text-storage-sensitive-data",
                                    "name": "Clear-text storage of sensitive information",
                                    "severity": "error",
                                    "tags": [
                                        "security",
                                        "external/cwe/cwe-312",
                                        "external/cwe/cwe-315",
                                        "external/cwe/cwe-359"
                                    ]
                                },
                                "url": "https://lgtm.com/rules/1510006386081"
                            }
                        },
                        {
                            "fixed": 4,
                            "new": 0,
                            "query": {
                                "id": 6780086,
                                "language": "python",
                                "name": "Unused local variable",
                                "pack": "com.lgtm/python-queries",
                                "properties": {
                                    "id": "py/unused-local-variable",
                                    "name": "Unused local variable",
                                    "severity": "recommendation",
                                    "tags": [
                                        "maintainability",
                                        "useless-code",
                                        "external/cwe/cwe-563"
                                    ]
                                },
                                "url": "https://lgtm.com/rules/6780086"
                            }
                        },
                        {
                            "fixed": 4,
                            "new": 0,
                            "query": {
                                "id": 1800095,
                                "language": "python",
                                "name": "Variable defined multiple times",
                                "pack": "com.lgtm/python-queries",
                                "properties": {
                                    "id": "py/multiple-definition",
                                    "name": "Variable defined multiple times",
                                    "severity": "warning",
                                    "tags": [
                                        "maintainability",
                                        "useless-code",
                                        "external/cwe/cwe-563"
                                    ]
                                },
                                "url": "https://lgtm.com/rules/1800095"
                            }
                        },
                        {
                            "fixed": 0,
                            "new": 0,
                            "query": {
                                "id": 3960089,
                                "language": "python",
                                "name": "Explicit returns mixed with implicit (fall through) returns",
                                "pack": "com.lgtm/python-queries",
                                "properties": {
                                    "id": "py/mixed-returns",
                                    "name": "Explicit returns mixed with implicit (fall through) returns",
                                    "severity": "recommendation",
                                    "tags": [
                                        "reliability",
                                        "maintainability"
                                    ]
                                },
                                "url": "https://lgtm.com/rules/3960089"
                            }
                        },
                        {
                            "fixed": 2,
                            "new": 0,
                            "query": {
                                "id": 1780094,
                                "language": "python",
                                "name": "Wrong number of arguments in a call",
                                "pack": "com.lgtm/python-queries",
                                "properties": {
                                    "id": "py/call/wrong-arguments",
                                    "name": "Wrong number of arguments in a call",
                                    "severity": "error",
                                    "tags": [
                                        "reliability",
                                        "correctness",
                                        "external/cwe/cwe-685"
                                    ]
                                },
                                "url": "https://lgtm.com/rules/1780094"
                            }
                        },
                        {
                            "fixed": 0,
                            "new": 0,
                            "query": {
                                "id": 10030095,
                                "language": "python",
                                "name": "File is not always closed",
                                "pack": "com.lgtm/python-queries",
                                "properties": {
                                    "id": "py/file-not-closed",
                                    "name": "File is not always closed",
                                    "severity": "warning",
                                    "tags": [
                                        "efficiency",
                                        "correctness",
                                        "resources",
                                        "external/cwe/cwe-772"
                                    ]
                                },
                                "url": "https://lgtm.com/rules/10030095"
                            }
                        }
                    ],
                    "fixed": 11,
                    "language": "python",
                    "new": 0,
                    "status": "success",
                    "status-message": "11 fixed alerts"
                }
            ],
            "results-url": "https://lgtm.com/projects/g/my-devsecops/moon/rev/pr-525d2cd0df76e6ba1e5a47c920b61cacb8e4068e",
            "status": "success",
            "status-message": "Analysis succeeded"
        }
    }
}
```

#### Human Readable Output

>### Results
>|id|languages|results-url|status|status-message|
>|---|---|---|---|---|
>| 525d2cd0df76e6ba1e5a47c920b61cacb8e4068e | {'language': 'python', 'status': 'success', 'status-message': '11 fixed alerts', 'new': 0, 'fixed': 11, 'alerts': [{'query': {'id': 9980089, 'pack': 'com.lgtm/python-queries', 'name': 'Statement has no effect', 'language': 'python', 'properties': {'id': 'py/ineffectual-statement', 'name': 'Statement has no effect', 'severity': 'recommendation', 'tags': ['maintainability', 'useless-code', 'external/cwe/cwe-561']}, 'url': 'https:<span>//</span>lgtm.com/rules/9980089'}, 'new': 0, 'fixed': 0}, {'query': {'id': 1510006386081, 'pack': 'com.lgtm/python-queries', 'name': 'Clear-text storage of sensitive information', 'language': 'python', 'properties': {'id': 'py/clear-text-storage-sensitive-data', 'name': 'Clear-text storage of sensitive information', 'severity': 'error', 'tags': ['security', 'external/cwe/cwe-312', 'external/cwe/cwe-315', 'external/cwe/cwe-359']}, 'url': 'https:<span>//</span>lgtm.com/rules/1510006386081'}, 'new': 0, 'fixed': 1}, {'query': {'id': 6780086, 'pack': 'com.lgtm/python-queries', 'name': 'Unused local variable', 'language': 'python', 'properties': {'id': 'py/unused-local-variable', 'name': 'Unused local variable', 'severity': 'recommendation', 'tags': ['maintainability', 'useless-code', 'external/cwe/cwe-563']}, 'url': 'https:<span>//</span>lgtm.com/rules/6780086'}, 'new': 0, 'fixed': 4}, {'query': {'id': 1800095, 'pack': 'com.lgtm/python-queries', 'name': 'Variable defined multiple times', 'language': 'python', 'properties': {'id': 'py/multiple-definition', 'name': 'Variable defined multiple times', 'severity': 'warning', 'tags': ['maintainability', 'useless-code', 'external/cwe/cwe-563']}, 'url': 'https:<span>//</span>lgtm.com/rules/1800095'}, 'new': 0, 'fixed': 4}, {'query': {'id': 3960089, 'pack': 'com.lgtm/python-queries', 'name': 'Explicit returns mixed with implicit (fall through) returns', 'language': 'python', 'properties': {'id': 'py/mixed-returns', 'name': 'Explicit returns mixed with implicit (fall through) returns', 'severity': 'recommendation', 'tags': ['reliability', 'maintainability']}, 'url': 'https:<span>//</span>lgtm.com/rules/3960089'}, 'new': 0, 'fixed': 0}, {'query': {'id': 1780094, 'pack': 'com.lgtm/python-queries', 'name': 'Wrong number of arguments in a call', 'language': 'python', 'properties': {'id': 'py/call/wrong-arguments', 'name': 'Wrong number of arguments in a call', 'severity': 'error', 'tags': ['reliability', 'correctness', 'external/cwe/cwe-685']}, 'url': 'https:<span>//</span>lgtm.com/rules/1780094'}, 'new': 0, 'fixed': 2}, {'query': {'id': 10030095, 'pack': 'com.lgtm/python-queries', 'name': 'File is not always closed', 'language': 'python', 'properties': {'id': 'py/file-not-closed', 'name': 'File is not always closed', 'severity': 'warning', 'tags': ['efficiency', 'correctness', 'resources', 'external/cwe/cwe-772']}, 'url': 'https:<span>//</span>lgtm.com/rules/10030095'}, 'new': 0, 'fixed': 0}]} | https://lgtm.com/projects/g/my-devsecops/moon/rev/pr-525d2cd0df76e6ba1e5a47c920b61cacb8e4068e | success | Analysis succeeded |


### lgtm-get-project
***
Get project by numeric identifier


#### Base Command

`lgtm-get-project`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project-id | The numeric project identifier | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LGTM.project_details.languages.grade | String | The grade of the code for this language. | 
| LGTM.project_details.id | Unknown | LGTM Project id | 
| LGTM.project_details.name | Unknown | LGTM Project name | 


#### Command Example
```!lgtm-get-project project-id=1512319787549```

#### Context Example
```json
{
    "LGTM": {
        "project_details": {
            "id": 1512319787549,
            "languages": [
                {
                    "alerts": 11,
                    "analysis-date": "2020-10-28T22:12:58.491+0000",
                    "commit-date": "2020-09-09T14:53:17.000+0000",
                    "commit-id": "39eb3dc0c7e86d0b943df1be922b173068010bf5",
                    "grade": "E",
                    "language": "python",
                    "lines": 127,
                    "status": "success"
                }
            ],
            "name": "my-devsecops/moon",
            "url": "https://lgtm.com/projects/g/my-devsecops/moon",
            "url-identifier": "g/my-devsecops/moon"
        }
    }
}
```

#### Human Readable Output

>### Results
>|id|languages|name|url|url-identifier|
>|---|---|---|---|---|
>| 1512319787549 | {'language': 'python', 'status': 'success', 'alerts': 11, 'lines': 127, 'commit-id': '39eb3dc0c7e86d0b943df1be922b173068010bf5', 'commit-date': '2020-09-09T14:53:17.000+0000', 'analysis-date': '2020-10-28T22:12:58.491+0000', 'grade': 'E'} | my-devsecops/moon | https://lgtm.com/projects/g/my-devsecops/moon | g/my-devsecops/moon |


### lgtm-get-project-by-url-identifier
***
Get project by URL identifier


#### Base Command

`lgtm-get-project-by-url-identifier`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| provider | The first part of the URL identifier of a project, which represents the repository host. | Required | 
| org | The second part of the URL identifier of a project, the organization. | Required | 
| name | The third part of the URL identifier of a project, the repository name. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LGTM.project_details.languages.grade | String | The grade of the code for this language. | 
| LGTM.project_details.id | Unknown | LGTM Project id | 
| LGTM.project_details.name | Unknown | LGTM Project name | 


#### Command Example
```!lgtm-get-project-by-url-identifier name=moon org=my-devsecops provider=g```

#### Context Example
```json
{
    "LGTM": {
        "project_details": {
            "id": 1512319787549,
            "languages": [
                {
                    "alerts": 11,
                    "analysis-date": "2020-10-28T22:12:58.491+0000",
                    "commit-date": "2020-09-09T14:53:17.000+0000",
                    "commit-id": "39eb3dc0c7e86d0b943df1be922b173068010bf5",
                    "grade": "E",
                    "language": "python",
                    "lines": 127,
                    "status": "success"
                }
            ],
            "name": "my-devsecops/moon",
            "url": "https://lgtm.com/projects/g/my-devsecops/moon",
            "url-identifier": "g/my-devsecops/moon"
        }
    }
}
```

#### Human Readable Output

>### Results
>|id|languages|name|url|url-identifier|
>|---|---|---|---|---|
>| 1512319787549 | {'language': 'python', 'status': 'success', 'alerts': 11, 'lines': 127, 'commit-id': '39eb3dc0c7e86d0b943df1be922b173068010bf5', 'commit-date': '2020-09-09T14:53:17.000+0000', 'analysis-date': '2020-10-28T22:12:58.491+0000', 'grade': 'E'} | my-devsecops/moon | https://lgtm.com/projects/g/my-devsecops/moon | g/my-devsecops/moon |


### lgtm-get-project-config
***
Get configuration for a project identified by numeric identifier


#### Base Command

`lgtm-get-project-config`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project-id | The numeric project identifier | Required | 
| source | The type of project configuration to retrieve. If this  meter isn't specified, the request retrieves the effective configuration. That is, the configuration that is actually applied to the project, which may be from:   the repository   the administrator-set, project configuration   the global configuration.  If you do specify this value, it must be one of:     `repository` to retrieve the configuration specified by a YAML file in the repository. A 404 status is returned if there is no repository configuration.      `administrator` to retrieve the administrator-set, project configuration. A 404 status is returned if there is no administrator configuration.  | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!lgtm-get-project-config project-id="1511896439667"```

#### Context Example
```json
{
    "LGTM": {
        "config": "path_classifiers:\n  test: \"**/*_test.py\"\nqueries:\n- exclude: \"*\"\n- include:\n    tags: \"security\"\n"
    }
}
```

#### Human Readable Output

>### Project Config
>|Config|
>|---|
>| path_classifiers:<br/>  test: "**/*_test.py"<br/>queries:<br/>- exclude: "*"<br/>- include:<br/>    tags: "security"<br/> |


### lgtm-get-projects
***
List projects


#### Base Command

`lgtm-get-projects`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of projects to return in each response (1-100). | Optional | 
| start | An opaque identifier generated by the API. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LGTM.project-list.data.id | Number | The numeric identifier of the project. | 
| LGTM.project-list.data.url-identifier | String | The URL identifier of the project. | 
| LGTM.project-list.data.name | String | The display name of the project. | 
| LGTM.project-list.data.url | String | The full URL of the project on LGTM. | 
| LGTM.project-list.nextPageUrl | String | The URL to retrieve the next page of projects. Omitted if there is no next page. | 


#### Command Example
```!lgtm-get-projects limit=10```

#### Context Example
```json
{
    "LGTM": {
        "project_list": {
            "data": [
                {
                    "id": 890003,
                    "name": "FountainJS/fountain-generator",
                    "url": "https://lgtm.com/projects/g/FountainJS/fountain-generator",
                    "url-identifier": "g/FountainJS/fountain-generator"
                },
                {
                    "id": 890022,
                    "name": "d3/d3-interpolate",
                    "url": "https://lgtm.com/projects/g/d3/d3-interpolate",
                    "url-identifier": "g/d3/d3-interpolate"
                },
                {
                    "id": 890042,
                    "name": "BanManagement/BanManager",
                    "url": "https://lgtm.com/projects/g/BanManagement/BanManager",
                    "url-identifier": "g/BanManagement/BanManager"
                },
                {
                    "id": 890045,
                    "name": "pull-stream/stream-to-pull-stream",
                    "url": "https://lgtm.com/projects/g/pull-stream/stream-to-pull-stream",
                    "url-identifier": "g/pull-stream/stream-to-pull-stream"
                },
                {
                    "id": 890048,
                    "name": "scijs/save-pixels",
                    "url": "https://lgtm.com/projects/g/scijs/save-pixels",
                    "url-identifier": "g/scijs/save-pixels"
                },
                {
                    "id": 890053,
                    "name": "forge/roaster",
                    "url": "https://lgtm.com/projects/g/forge/roaster",
                    "url-identifier": "g/forge/roaster"
                },
                {
                    "id": 890066,
                    "name": "puleos/object-hash",
                    "url": "https://lgtm.com/projects/g/puleos/object-hash",
                    "url-identifier": "g/puleos/object-hash"
                },
                {
                    "id": 890070,
                    "name": "TooTallNate/plist.js",
                    "url": "https://lgtm.com/projects/g/TooTallNate/plist.js",
                    "url-identifier": "g/TooTallNate/plist.js"
                },
                {
                    "id": 890073,
                    "name": "automatictester/lightning",
                    "url": "https://lgtm.com/projects/g/automatictester/lightning",
                    "url-identifier": "g/automatictester/lightning"
                },
                {
                    "id": 890076,
                    "name": "fjakobs/async.js",
                    "url": "https://lgtm.com/projects/g/fjakobs/async.js",
                    "url-identifier": "g/fjakobs/async.js"
                }
            ],
            "nextPageUrl": "https://lgtm.com/api/v1.0/projects?limit=10&start=AfyWmuiCRajZNPY1kkCBgpu1T2dXj1Nec9-hHV2I0Lmb4g2rUPgqvfkH9uaDhzNA3OUoI5xkAvNfd9mIMNNoHZQ-W4BHdNL6fshdYcZXUwQIzFxnzQszrWgD-o4gYW1nEg"
        }
    }
}
```

#### Human Readable Output

>### Results
>|data|nextPageUrl|
>|---|---|
>| {'id': 890003, 'url-identifier': 'g/FountainJS/fountain-generator', 'name': 'FountainJS/fountain-generator', 'url': 'https://lgtm.com/projects/g/FountainJS/fountain-generator'},<br/>{'id': 890022, 'url-identifier': 'g/d3/d3-interpolate', 'name': 'd3/d3-interpolate', 'url': 'https://lgtm.com/projects/g/d3/d3-interpolate'},<br/>{'id': 890042, 'url-identifier': 'g/BanManagement/BanManager', 'name': 'BanManagement/BanManager', 'url': 'https://lgtm.com/projects/g/BanManagement/BanManager'},<br/>{'id': 890045, 'url-identifier': 'g/pull-stream/stream-to-pull-stream', 'name': 'pull-stream/stream-to-pull-stream', 'url': 'https://lgtm.com/projects/g/pull-stream/stream-to-pull-stream'},<br/>{'id': 890048, 'url-identifier': 'g/scijs/save-pixels', 'name': 'scijs/save-pixels', 'url': 'https://lgtm.com/projects/g/scijs/save-pixels'},<br/>{'id': 890053, 'url-identifier': 'g/forge/roaster', 'name': 'forge/roaster', 'url': 'https://lgtm.com/projects/g/forge/roaster'},<br/>{'id': 890066, 'url-identifier': 'g/puleos/object-hash', 'name': 'puleos/object-hash', 'url': 'https://lgtm.com/projects/g/puleos/object-hash'},<br/>{'id': 890070, 'url-identifier': 'g/TooTallNate/plist.js', 'name': 'TooTallNate/plist.js', 'url': 'https://lgtm.com/projects/g/TooTallNate/plist.js'},<br/>{'id': 890073, 'url-identifier': 'g/automatictester/lightning', 'name': 'automatictester/lightning', 'url': 'https://lgtm.com/projects/g/automatictester/lightning'},<br/>{'id': 890076, 'url-identifier': 'g/fjakobs/async.js', 'name': 'fjakobs/async.js', 'url': 'https://lgtm.com/projects/g/fjakobs/async.js'} | https://lgtm.com/api/v1.0/projects?limit=10&start=AfyWmuiCRajZNPY1kkCBgpu1T2dXj1Nec9-hHV2I0Lmb4g2rUPgqvfkH9uaDhzNA3OUoI5xkAvNfd9mIMNNoHZQ-W4BHdNL6fshdYcZXUwQIzFxnzQszrWgD-o4gYW1nEg |


### lgtm-get-version
***
Version information


#### Base Command

`lgtm-get-version`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LGTM.version.apiVersion | String | The version number of the API. | 


#### Command Example
```!lgtm-get-version```

#### Context Example
```json
{
    "LGTM": {
        "version": {
            "apiVersion": "1.0"
        }
    }
}
```

#### Human Readable Output

>### Results
>|apiVersion|
>|---|
>| 1.0 |


### lgtm-request-analysis
***
Run analysis of a specific commit


#### Base Command

`lgtm-request-analysis`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project-id | The numeric project identifier. | Required | 
| commit | The identifier of the commit to analyze. | Required | 
| language | The language codes of the languages to analyze. For a list of available languages, see [Supported languages](https://lgtm.com/help/lgtm/analysis-faqs#which-languages-are-supported). To specify more than one language, this  meter can be repeated. If no language is specified, all the project's languages will be analyzed.  | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LGTM.analysis.id | Unknown | LGTM request id | 
| LGTM.analysis.status | Unknown | LGTM analysis status | 
| LGTM.analysis_request.task-result.id | Unknown | LGTM analysis task id | 
| LGTM.analysis_request.task-result.commit-id | Unknown | LGTM analysis commit id | 


#### Command Example
```!lgtm-request-analysis commit=b1b136e071533d78053be506d32f79417651727d project-id=1511925128331 language=python```

#### Context Example
```json
{
    "LGTM": {
        "analysis_request": {
            "id": 1512897038814,
            "status": "done",
            "task-result": {
                "commit-id": "b1b136e071533d78053be506d32f79417651727d",
                "id": "ef0e7bd0421cb2cc2e9cb7ab5ce3cba109ee2a95",
                "languages": [
                    {
                        "alerts": 5,
                        "analysis-date": "2020-11-04T07:37:31.324+0000",
                        "commit-date": "2020-05-31T14:33:52.000+0000",
                        "commit-id": "b1b136e071533d78053be506d32f79417651727d",
                        "language": "python",
                        "lines": 87,
                        "status": "success"
                    }
                ],
                "log-url": "https://lgtm.com/projects/g/my-tradingbot/scanner/logs/analysis/ef0e7bd0421cb2cc2e9cb7ab5ce3cba109ee2a95",
                "project": {
                    "id": 1511925128331,
                    "name": "my-tradingbot/scanner",
                    "url": "https://lgtm.com/projects/g/my-tradingbot/scanner",
                    "url-identifier": "g/my-tradingbot/scanner"
                },
                "results-url": "https://lgtm.com/projects/g/my-tradingbot/scanner/analysis/ef0e7bd0421cb2cc2e9cb7ab5ce3cba109ee2a95/files"
            },
            "task-result-url": "https://lgtm.com/api/v1.0/analyses/ef0e7bd0421cb2cc2e9cb7ab5ce3cba109ee2a95",
            "task-type": "analysis"
        }
    }
}
```

#### Human Readable Output

>### Results
>|id|status|task-result|task-result-url|task-type|
>|---|---|---|---|---|
>| 1512897038814 | done | id: ef0e7bd0421cb2cc2e9cb7ab5ce3cba109ee2a95<br/>project: {"id": 1511925128331, "url-identifier": "g/my-tradingbot/scanner", "name": "my-tradingbot/scanner", "url": "https://lgtm.com/projects/g/my-tradingbot/scanner"}<br/>commit-id: b1b136e071533d78053be506d32f79417651727d<br/>languages: {'language': 'python', 'status': 'success', 'alerts': 5, 'lines': 87, 'commit-id': 'b1b136e071533d78053be506d32f79417651727d', 'commit-date': '2020-05-31T14:33:52.000+0000', 'analysis-date': '2020-11-04T07:37:31.324+0000'}<br/>log-url: https://lgtm.com/projects/g/my-tradingbot/scanner/logs/analysis/ef0e7bd0421cb2cc2e9cb7ab5ce3cba109ee2a95<br/>results-url: https://lgtm.com/projects/g/my-tradingbot/scanner/analysis/ef0e7bd0421cb2cc2e9cb7ab5ce3cba109ee2a95/files | https://lgtm.com/api/v1.0/analyses/ef0e7bd0421cb2cc2e9cb7ab5ce3cba109ee2a95 | analysis |


### lgtm-request-review
***
Run code review for a patch


#### Base Command

`lgtm-request-review`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project-id | The numeric project identifier. | Required | 
| base | The identifier for the base commit. | Required | 
| external-id | Your reference number for the code review. | Required | 
| callback-url | The callback URL for LGTM to post to on completion of the review. When the code review is complete, the API sends an HTTP POST request to the callback URL with the result of the code review in the request body. The code review results in the request body are identical to the results accessed through the [`/codereviews/{review-id}`](https://lgtm.com/help/lgtm/api/api-v1#opIdgetCodeReview) end-point. If you specify a `callback-secret`, the request also includes an `x-lgtm-signature` header with a digital signature of the request's contents.  | Optional | 
| callback-secret | The `callback-secret` is used to compute a signature which is included in the `x-lgtm-signature` header of the callback response. The receiver of the callback can check the validity of the response by computing the signature using HMAC-SHA1 and verifying that it matches the `x-lgtm-signature` header value. The HMAC algorithm requires byte sequences as inputs for both the secret and the message. The callback secret string must be converted to bytes using UTF-8 encoding. The response body should ideally be read as a plain byte sequence. Conversion to, for example a JSON object, and back to a byte sequence might change the formatting, and would invalidate the signature.  | Optional | 
| patch-entry-id | Entry ID of the Patch File , you can use git diff --binary to generate patch file | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LGTM.code_review_request.id | Unknown | LGTM Code Review request id | 
| LGTM.code_review_request.status | Unknown | LGTM Code Review request status | 
| LGTM.code_review_request.task-result.id | Unknown | LGTM Code Review request task id | 


#### Command Example
```!lgtm-request-review project-id=1512319787549 base=405fc6ea44910177f48db9b2eb6839efb4211743 external-id=49  patch-entry-id=478@ed5c5f6c-726a-4e62-85dc-8b1aad179194```

#### Context Example
```json
{
    "LGTM": {
        "code_review_request": {
            "id": 1512842530470,
            "status": "pending",
            "task-result": {
                "id": "cccab75368f5e896c17f5155f759bad72fdb6adf",
                "languages": [
                    {
                        "alerts": [],
                        "fixed": 0,
                        "language": "python",
                        "new": 0,
                        "status": "pending",
                        "status-message": "Starting up"
                    }
                ],
                "results-url": "https://lgtm.com/projects/g/my-devsecops/moon/rev/pr-cccab75368f5e896c17f5155f759bad72fdb6adf",
                "status": "pending",
                "status-message": "Starting up"
            },
            "task-result-url": "https://lgtm.com/api/v1.0/codereviews/cccab75368f5e896c17f5155f759bad72fdb6adf",
            "task-type": "codereview"
        }
    }
}
```

#### Human Readable Output

>### Results
>|id|status|task-result|task-result-url|task-type|
>|---|---|---|---|---|
>| 1512842530470 | pending | id: cccab75368f5e896c17f5155f759bad72fdb6adf<br/>results-url: https://lgtm.com/projects/g/my-devsecops/moon/rev/pr-cccab75368f5e896c17f5155f759bad72fdb6adf<br/>status: pending<br/>status-message: Starting up<br/>languages: {'language': 'python', 'status': 'pending', 'status-message': 'Starting up', 'new': 0, 'fixed': 0, 'alerts': []} | https://lgtm.com/api/v1.0/codereviews/cccab75368f5e896c17f5155f759bad72fdb6adf | codereview |


### lgtm-create-query-job
***
Run a CodeQL query on one or more projects


#### Base Command

`lgtm-create-query-job`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| language | The [language](https://lgtm.com/help/lgtm/analysis-faqs#which-languages-are-supported) you want to analyze.  | Required | 
| project-id | The identifier of the project to analyze. Either `project-id` or `projects-list` must be specified. | Required | 
| query-list | The CodeQL query stored in an XSOAR list | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LGTM.Queries.task-result.id | Unknown | Query ID | 


#### Command Example
```!lgtm-create-query-job language=python project-id=1511896439667 query-list=${lists.CodeQL-Queries-SQL_Injection}```

#### Context Example
```json
{
    "LGTM": {
        "queryjob": {
            "id": 1512871744413,
            "status": "pending",
            "task-result": {
                "id": "1877941903313451628",
                "result-url": "https://lgtm.com/query/1877941903313451628",
                "stats": {
                    "failed": 0,
                    "pending": 0,
                    "success-with-result": 0,
                    "success-without-result": 0,
                    "successful": 0
                }
            },
            "task-result-url": "https://lgtm.com/api/v1.0/queryjobs/1877941903313451628",
            "task-type": "queryjob"
        }
    }
}
```

#### Human Readable Output

>### Results
>|id|status|task-result|task-result-url|task-type|
>|---|---|---|---|---|
>| 1512871744413 | pending | id: 1877941903313451628<br/>stats: {"successful": 0, "success-with-result": 0, "success-without-result": 0, "failed": 0, "pending": 0}<br/>result-url: https://lgtm.com/query/1877941903313451628 | https://lgtm.com/api/v1.0/queryjobs/1877941903313451628 | queryjob |


### lgtm-get-query-job
***
Get the status of a query job


#### Base Command

`lgtm-get-query-job`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| queryjob-id | The identifier of the query job, from the `task-result` given in the response to the initial `POST /queryjobs` request. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LGTM.queryjob.id | String | The identifier for the QueryJob. | 


#### Command Example
```!lgtm-get-query-job queryjob-id=2651230846634222938```

#### Context Example
```json
{
    "LGTM": {
        "queryjob": {
            "id": "2651230846634222938",
            "result-url": "https://lgtm.com/query/2651230846634222938",
            "stats": {
                "failed": 0,
                "pending": 0,
                "success-with-result": 1,
                "success-without-result": 0,
                "successful": 1
            }
        }
    }
}
```

#### Human Readable Output

>### Results
>|id|result-url|stats|
>|---|---|---|
>| 2651230846634222938 | https://lgtm.com/query/2651230846634222938 | successful: 1<br/>success-with-result: 1<br/>success-without-result: 0<br/>failed: 0<br/>pending: 0 |


### lgtm-get-query-job-results-for-project
***
Fetch the results of a query job for a specific project


#### Base Command

`lgtm-get-query-job-results-for-project`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| queryjob-id | The identifier of the query job, from the `task-result` given in the response to the initial `POST /queryjobs` request. | Required | 
| project-id | The identifier for the project. | Required | 
| start | Start point for the page of results. | Optional | 
| limit | The maximum number of results to display (less than 100). | Optional | 
| nofilter | Include results that are not part of the source tree. These results are filtered out by default. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LGTM.queryjob-project-results.data.line | Number | LGTM Query Job Project Data Line | 
| LGTM.queryjob-project-results.data.file | String | LGTM Query Job Project Data File | 
| LGTM.queryjob-project-results.data.value | String | LGTM Query Job Project Data Value | 
| LGTM.queryjob-project-results.data.url | String | LGTM Query Job Project Data URL | 
| LGTM.queryjob-project-results.next | String | URL for retrieving the next part of the results \(if applicable\). | 
| LGTM.queryjob_project_results.project.id | Unknown | Project ID | 


#### Command Example
```!lgtm-get-query-job-results-for-project project-id=1511896439667 queryjob-id=2651230846634222938```

#### Context Example
```json
{
    "LGTM": {
        "queryjob_project_results": {
            "columns": [
                "col0",
                "src",
                "sink",
                "col3",
                "col4",
                "col5"
            ],
            "data": [
                [
                    {
                        "file": "/src/atom.py",
                        "line": 45,
                        "url": "https://lgtm.com/projects/g/my-devsecops/galaxy/snapshot/472c1d3933ec0046fd914ef04ff4770454325ccb/files/src/atom.py#L45",
                        "value": "BinaryExpr"
                    },
                    {
                        "file": "/src/atom.py",
                        "line": 42,
                        "url": "https://lgtm.com/projects/g/my-devsecops/galaxy/snapshot/472c1d3933ec0046fd914ef04ff4770454325ccb/files/src/atom.py#L42",
                        "value": "externally controlled string"
                    },
                    {
                        "file": "/src/atom.py",
                        "line": 45,
                        "url": "https://lgtm.com/projects/g/my-devsecops/galaxy/snapshot/472c1d3933ec0046fd914ef04ff4770454325ccb/files/src/atom.py#L45",
                        "value": "externally controlled string"
                    },
                    {
                        "value": "This SQL query depends on $@."
                    },
                    {
                        "file": "/src/atom.py",
                        "line": 42,
                        "url": "https://lgtm.com/projects/g/my-devsecops/galaxy/snapshot/472c1d3933ec0046fd914ef04ff4770454325ccb/files/src/atom.py#L42",
                        "value": "username"
                    },
                    {
                        "value": "a user-provided value"
                    }
                ]
            ],
            "project": {
                "id": 1511896439667,
                "name": "my-devsecops/galaxy",
                "url": "https://lgtm.com/projects/g/my-devsecops/galaxy",
                "url-identifier": "g/my-devsecops/galaxy"
            }
        }
    }
}
```

#### Human Readable Output

>### Results
>|columns|data|project|
>|---|---|---|
>| col0,<br/>src,<br/>sink,<br/>col3,<br/>col4,<br/>col5 | [{'line': 45, 'file': '/src/atom.py', 'value': 'BinaryExpr', 'url': 'https://lgtm.com/projects/g/my-devsecops/galaxy/snapshot/472c1d3933ec0046fd914ef04ff4770454325ccb/files/src/atom.py#L45'}, {'line': 42, 'file': '/src/atom.py', 'value': 'externally controlled string', 'url': 'https://lgtm.com/projects/g/my-devsecops/galaxy/snapshot/472c1d3933ec0046fd914ef04ff4770454325ccb/files/src/atom.py#L42'}, {'line': 45, 'file': '/src/atom.py', 'value': 'externally controlled string', 'url': 'https://lgtm.com/projects/g/my-devsecops/galaxy/snapshot/472c1d3933ec0046fd914ef04ff4770454325ccb/files/src/atom.py#L45'}, {'value': 'This SQL query depends on $@.'}, {'line': 42, 'file': '/src/atom.py', 'value': 'username', 'url': 'https://lgtm.com/projects/g/my-devsecops/galaxy/snapshot/472c1d3933ec0046fd914ef04ff4770454325ccb/files/src/atom.py#L42'}, {'value': 'a user-provided value'}] | id: 1511896439667<br/>url-identifier: g/my-devsecops/galaxy<br/>name: my-devsecops/galaxy<br/>url: https://lgtm.com/projects/g/my-devsecops/galaxy |


### lgtm-get-query-job-results-overview
***
Provide a summary of results for the projects in the query job


#### Base Command

`lgtm-get-query-job-results-overview`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| queryjob-id | The identifier of the query job, from the `task-result` given in the response to the initial `POST /queryjobs` request. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LGTM.queryjob-results-overview.data.status | String | Describes whether the query was sucessfully executed against the project. | 
| LGTM.queryjob-results-overview.data.total | Number | Number of results returned by the query. This is  oken down further into \`internal\` and \`external\` results. Only applies if \`status\` is \`success\`.  | 
| LGTM.queryjob-results-overview.data.internal | Number | Number of results that refer to elements within the source tree. Only applies if \`status\` is \`success\`. | 
| LGTM.queryjob-results-overview.data.external | Number | Number of results that refer to elements outside the source tree \(e.g., li aries\). Only applies if \`status\` is \`success\`. | 
| LGTM.queryjob-results-overview.data.error | String | Error message. Only applies if \`status\` is \`error\`. | 
| LGTM.queryjob-results-overview.next | String | LGTM Query Job Results Overview Next | 


#### Command Example
```!lgtm-get-query-job-results-overview queryjob-id=206061421522356021```

#### Context Example
```json
{
    "LGTM": {
        "queryjob_results_overview": {
            "data": [
                {
                    "external": 0,
                    "internal": 0,
                    "project": {
                        "id": 1511896439667,
                        "name": "my-devsecops/galaxy",
                        "url": "https://lgtm.com/projects/g/my-devsecops/galaxy",
                        "url-identifier": "g/my-devsecops/galaxy"
                    },
                    "status": "success",
                    "total": 0
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Results
>|data|
>|---|
>| {'project': {'id': 1511896439667, 'url-identifier': 'g/my-devsecops/galaxy', 'name': 'my-devsecops/galaxy', 'url': 'https://lgtm.com/projects/g/my-devsecops/galaxy'}, 'status': 'success', 'total': 0, 'internal': 0, 'external': 0} |
