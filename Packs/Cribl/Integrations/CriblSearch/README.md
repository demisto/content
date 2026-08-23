Cribl Search is a search solution that allows you to query, retrieve, and manage search jobs, datasets, and saved searches across your Cribl Cloud deployment.
This integration was integrated and tested with version 4.17.0 of Cribl API.

## Configure CriblSearch in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Base URL | The base URL assigned to your organization: https://\$\{workspaceName\}-\$\{organizationId\}.cribl.cloud | True |
| Client ID |  | True |
| Client Secret |  | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### cribl-search-query

***
Runs a search query against Cribl Search and returns results.

#### Base Command

`cribl-search-query`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query_id | The ID of a saved query to execute. | Optional |
| job_id | The ID of an existing search job to retrieve results from. | Optional |
| query | The search query string to execute. | Optional |
| earliest | The start time for the search, in relative time or epoch seconds. | Optional |
| latest | The end time for the search, in relative time or epoch seconds. | Optional |
| sample_rate | The probability (0-1) of including each matching event (for example, 0.1 returns ~10%). If omitted, no sampling is applied. | Optional |
| force | Whether to force execution of a scheduled query. | Optional |
| page | The page number for pagination. | Optional |
| limit | The maximum number of results to return. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cribl.SearchQuery.events | Unknown | The list of events returned by the search \(parsed from the NDJSON response\). May be empty when the job is still queued/running. |
| Cribl.SearchQuery.isFinished | Boolean | Whether the search query has finished executing. |
| Cribl.SearchQuery.job | Object | The search job metadata associated with this query. |
| Cribl.SearchQuery.job.id | String | The unique identifier of the search job that produced these results. |
| Cribl.SearchQuery.job.query | String | The search query string executed by the job. |
| Cribl.SearchQuery.job.status | String | The current status of the search job \(for example, queued, running, completed\). |
| Cribl.SearchQuery.job.timeCreated | Number | The epoch \(ms\) when the search job was created. |
| Cribl.SearchQuery.offset | Number | The offset within the result set used for pagination. |
| Cribl.SearchQuery.persistedEventCount | Number | The number of events persisted in the result set. |
| Cribl.SearchQuery.totalEventCount | Number | Total number of events matched by the query. |

#### Command example

```!cribl-search-query query="dataset=\"cribl_search_sample\" | project method, source, status, url | take 5" earliest="-24h" latest="now" limit=3```

#### Context Example

```json
{
    "Cribl": {
        "SearchQuery": {
            "events": [],
            "isFinished": false,
            "job": {
                "earliest": "-24h",
                "id": "1777447153600.MgWe3v",
                "latest": "now",
                "query": "dataset=\"cribl_search_sample\" | project method, source, status, url | take 5",
                "status": "queued",
                "timeCreated": 1777447153600
            },
            "limit": 3,
            "offset": 0,
            "persistedEventCount": 0,
            "totalEventCount": 0
        }
    }
}
```

#### Human Readable Output

>### Search Query - Job Info
>
>|Is Finished|Job ID|Status|Query|Earliest|Latest|Total Events|
>|---|---|---|---|---|---|---|
>| false | 1777447153600.MgWe3v | queued | dataset="cribl_search_sample" \| project method, source, status, url \| take 5 | -24h | now | 0 |

### cribl-search-status

***
Retrieves the status of a specific search job.

#### Base Command

`cribl-search-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | The unique identifier of the search job. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cribl.SearchStatus.pendingComputeNodeStatuses | Object | The counts of pending compute nodes \(warm/cold\) for the job. |
| Cribl.SearchStatus.status | String | The current status of the search job \(for example, queued, running, completed\). |
| Cribl.SearchStatus.timeCreated | Number | The epoch \(ms\) when the search job was created. |
| Cribl.SearchStatus.timeStarted | Number | The epoch \(ms\) when the search job started executing. This is only set once the job leaves the queued state. |
| Cribl.SearchStatus.timeCompleted | Number | The epoch \(ms\) when the search job completed. This is only set after the job finishes. |

#### Command example

```!cribl-search-status job_id="1777207943198.pb0ZZ0"```

#### Context Example

```json
{
    "Cribl": {
        "SearchStatus": {
            "cacheStatusesByStageId": {
                "root": {
                    "cribl_search_sample": {
                        "cacheStatus": "miss",
                        "computeType": "v1",
                        "reason": "Not a Lake Dataset",
                        "usedCache": false
                    }
                }
            },
            "pendingComputeNodeStatuses": {
                "countCold": 0,
                "countWarm": 0
            },
            "status": "completed",
            "timeCompleted": 1777207949675,
            "timeCreated": 1777207943198,
            "timeNow": 1777447157205,
            "timeStarted": 1777207943675
        }
    }
}
```

#### Human Readable Output

>### Search Job 1777207943198.pb0ZZ0 Status
>
>|Status|Time Started|Time Created|Time Completed|
>|---|---|---|---|
>| completed | 1777207943675 | 1777207943198 | 1777207949675 |

### cribl-search-result

***
Retrieves the results of a completed search job.

#### Base Command

`cribl-search-result`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | The unique identifier of the search job. | Required |
| lower_bound | The lower time bound for results (inclusive, epoch). | Optional |
| upper_bound | The upper time bound for results (exclusive, epoch). | Optional |
| page | The page number for pagination. | Optional |
| limit | The maximum number of results to return. Default is 50. | Optional |
| all_results | Whether to return all results. If true, overrides the limit argument. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cribl.SearchResult.events | Unknown | The list of events returned by the search \(parsed from the NDJSON response\). Each element is a free-form event object whose shape depends on the dataset and the query's projection. |
| Cribl.SearchResult.isFinished | Boolean | Whether the search job has finished executing. |
| Cribl.SearchResult.job | Object | The search job metadata associated with these results. |
| Cribl.SearchResult.job.id | String | The unique identifier of the search job. |
| Cribl.SearchResult.job.query | String | The search query string executed by the job. |
| Cribl.SearchResult.job.status | String | The current status of the search job \(for example, queued, running, completed\). |
| Cribl.SearchResult.job.timeCreated | Number | The epoch \(ms\) when the search job was created. |
| Cribl.SearchResult.offset | Number | The offset within the result set used for pagination. |
| Cribl.SearchResult.persistedEventCount | Number | The number of events persisted in the result set. |
| Cribl.SearchResult.totalEventCount | Number | The total number of events matched by the search job. |

#### Command example

```!cribl-search-result job_id="1777207943198.pb0ZZ0" limit=5```

#### Context Example

```json
{
    "Cribl": {
        "SearchResult": {
            "events": [
                {
                    "source": "s3://cribl-search-example/data/vpcflowlogs/2026/04/26/12/CriblOut-0RRoVn.2.raw.gz"
                },
                {
                    "source": "s3://cribl-search-example/data/vpcflowlogs/2026/04/26/12/CriblOut-0ZBHzD.2.raw.gz"
                },
                {
                    "source": "s3://cribl-search-example/data/vpcflowlogs/2026/04/26/12/CriblOut-2w9JEP.2.raw.gz"
                },
                {
                    "source": "s3://cribl-search-example/data/vpcflowlogs/2026/04/26/12/CriblOut-0RRoVn.2.raw.gz"
                },
                {
                    "source": "s3://cribl-search-example/data/vpcflowlogs/2026/04/26/12/CriblOut-0ZBHzD.2.raw.gz"
                }
            ],
            "isFinished": true,
            "job": {
                "earliest": "-24h",
                "id": "1777207943198.pb0ZZ0",
                "latest": "now",
                "query": "dataset=\"cribl_search_sample\" | project method, source, status, url | take 5",
                "status": "completed",
                "timeCompleted": 1777207949675,
                "timeCreated": 1777207943198,
                "timeStarted": 1777207943675
            },
            "limit": 5,
            "offset": 0,
            "persistedEventCount": 5,
            "totalEventCount": 5
        }
    }
}
```

#### Human Readable Output

>### Search Job 1777207943198.pb0ZZ0 Results - Job Info
>
>|Is Finished|Job ID|Status|Query|Earliest|Latest|Total Events|
>|---|---|---|---|---|---|---|
>| true | 1777207943198.pb0ZZ0 | completed | dataset="cribl_search_sample" \| project method, source, status, url \| take 5 | -24h | now | 5 |
>
>### Search Job 1777207943198.pb0ZZ0 Results - Events
>
>|source|
>|---|
>| s3://cribl-search-example/data/vpcflowlogs/2026/04/26/12/CriblOut-0RRoVn.2.raw.gz |
>| s3://cribl-search-example/data/vpcflowlogs/2026/04/26/12/CriblOut-0ZBHzD.2.raw.gz |
>| s3://cribl-search-example/data/vpcflowlogs/2026/04/26/12/CriblOut-2w9JEP.2.raw.gz |
>| s3://cribl-search-example/data/vpcflowlogs/2026/04/26/12/CriblOut-0RRoVn.2.raw.gz |
>| s3://cribl-search-example/data/vpcflowlogs/2026/04/26/12/CriblOut-0ZBHzD.2.raw.gz |

### cribl-search-job-create

***
Creates a new search job in Cribl Search.

#### Base Command

`cribl-search-job-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The search query string. | Required |
| earliest | The start time for the search, in epoch seconds. | Optional |
| latest | The end time for the search, in epoch seconds. | Optional |
| sample_rate | The probability (0-1) of including each matching event (for example, 0.1 returns ~10%). If omitted, no sampling is applied. | Optional |
| num_events_before | The number of events to include before the target event. | Optional |
| num_events_after | The number of events to include after the target event. | Optional |
| target_event_time | The target event time (epoch seconds). | Optional |
| is_private | Whether the search job is private. Default is True. | Optional |
| set_options | A JSON string of additional search options. | Optional |
| expected_output_type | The expected output type for the search. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cribl.SearchJob.id | String | The unique identifier of the search job. |
| Cribl.SearchJob.user | String | The user identifier \(client ID\) that created the job. |
| Cribl.SearchJob.displayUsername | String | The display name of the user who created the job. |
| Cribl.SearchJob.group | String | The search group the job belongs to. |
| Cribl.SearchJob.query | String | The search query string executed by the job. |
| Cribl.SearchJob.status | String | The current status of the search job \(for example, queued, running, completed\). |
| Cribl.SearchJob.timeCreated | Number | The epoch \(ms\) when the search job was created. |
| Cribl.SearchJob.type | String | The type of search job \(for example, standard, dashboard\). |
| Cribl.SearchJob.usageGroupId | String | The identifier of the usage group the job is billed against. |
| Cribl.SearchJob.isPrivate | Boolean | Whether the search job is marked private. |
| Cribl.SearchJob.accelerated | Boolean | Whether the search job uses acceleration. |
| Cribl.SearchJob.earliest | String | The start time for the search, in relative time or epoch seconds. |
| Cribl.SearchJob.latest | String | The end time for the search, in relative time or epoch seconds. |
| Cribl.SearchJob.compatibilityChecks | Object | The compatibility check flags evaluated for the job. |
| Cribl.SearchJob.metadata | Object | The metadata about the query \(for example, datasets, providers, operators, and functions\). |
| Cribl.SearchJob.setOptions | Object | The additional search options provided when creating the job. |
| Cribl.SearchJob.stages | Unknown | The stages of the search job's execution plan. |
| Cribl.SearchJob.internal | Object | The internal job state \(compiled policies, role-derived limits, preprocessed query, etc.\). Returned on create; not normally returned by list/update. |
| Cribl.SearchJob.userDetails | Object | The details about the user/credential that created the job. |
| Cribl.SearchJob.userDetails.email | String | The email address of the user who created the job. |
| Cribl.SearchJob.userDetails.username | String | The username of the user \(or client ID, for API-credential users\) who created the job. |
| Cribl.SearchJob.userDetails.displayUsername | String | The display name of the user who created the job. |
| Cribl.SearchJob.userDetails.type | String | The type of user identity \(for example, apiCredential, sso\). |
| Cribl.SearchJob.userDetails.roles | Unknown | The roles assigned to the user. |

#### Command example

```!cribl-search-job-create query="dataset=\"cribl_search_sample\" | summarize cnt=count() by srcaddr"```

#### Context Example

```json
{
    "Cribl": {
        "SearchJob": {
            "accelerated": false,
            "compatibilityChecks": {
                "datatypes": false
            },
            "displayUsername": "example.user@example.com",
            "earliest": "-1h",
            "group": "default_search",
            "id": "1777447149939.xPWbOm",
            "internal": {
                "compiledPolicies": [
                    {
                        "actions": [
                            "*"
                        ],
                        "object": "*"
                    },
                    {
                        "actions": [
                            "GET"
                        ],
                        "object": "/system/users/EXAMPLECLIENTID0000000000000000@clients"
                    },
                    {
                        "actions": [
                            "PATCH"
                        ],
                        "object": "/system/users/EXAMPLECLIENTID0000000000000000@clients/info"
                    }
                ],
                "detectedKeyAccesses": {},
                "email": "example.user@example.com",
                "maxExecutors": 50,
                "maxResultsPerSearch": 50000,
                "maxRunningTimeRange": {
                    "maxSec": 86400
                },
                "preprocessedQuery": "dataset=\"cribl_search_sample\" | summarize cnt=count() by srcaddr",
                "roles": [
                    "search_user",
                    "org_user",
                    "ws_user"
                ]
            },
            "isPrivate": true,
            "latest": "now",
            "metadata": {
                "arguments": {},
                "cloudProvider": "aws",
                "computeTypes": {
                    "v1": 1
                },
                "datasets": {
                    "cribl_search_sample": 1
                },
                "functions": {
                    "count": 1
                },
                "operators": {
                    "dataset=\"cribl_search_sample\"": 1,
                    "summarize": 1
                },
                "providerTypes": {
                    "s3": 1
                },
                "providers": {
                    "cribl_s3sample_provider": 1
                }
            },
            "query": "dataset=\"cribl_search_sample\" | summarize cnt=count() by srcaddr",
            "setOptions": {},
            "stages": [
                {
                    "dependencies": [],
                    "filter": "(dataset == 'cribl_search_sample')",
                    "id": "root",
                    "resolvedDatasetIds": [
                        "cribl_search_sample"
                    ],
                    "searchConfig": {
                        "canComputeMetadataDistributively": false,
                        "datasets": [
                            "cribl_search_sample"
                        ],
                        "hasSendOperator": false,
                        "logicalPlans": {
                            "Combined": {
                                "root:0:2uw2": [
                                    {
                                        "condition": {
                                            "caseSensitive": false,
                                            "lhs": {
                                                "columnPath": [
                                                    "dataset"
                                                ],
                                                "type": "identifier"
                                            },
                                            "operator": "==",
                                            "rhs": {
                                                "literal": "cribl_search_sample",
                                                "type": "literal"
                                            },
                                            "type": "binaryOperation"
                                        },
                                        "type": "filter"
                                    }
                                ],
                                "root:1:tTTC": [
                                    {
                                        "aggregates": [
                                            {
                                                "assignee": {
                                                    "columnPath": [
                                                        "cnt"
                                                    ],
                                                    "type": "identifier"
                                                },
                                                "operation": {
                                                    "functionType": "aggregation",
                                                    "name": "count",
                                                    "parameters": [],
                                                    "type": "function"
                                                },
                                                "type": "assign"
                                            }
                                        ],
                                        "aggregationType": "summarize",
                                        "canDistributeAggregation": false,
                                        "groupBy": [
                                            {
                                                "columnPath": [
                                                    "srcaddr"
                                                ],
                                                "type": "identifier"
                                            }
                                        ],
                                        "isPreviewableOperation": true,
                                        "location": "coordinated",
                                        "type": "aggregate"
                                    }
                                ],
                                "root:3:uDgk": [
                                    {
                                        "type": "noop"
                                    }
                                ]
                            },
                            "Coordinated": {
                                ...
                            },
                            "Federated": {
                                ...
                            }
                        },
                        "orderedFieldNames": [
                            "srcaddr",
                            "cnt"
                        ],
                        "pipelines": {
                            "Combined": {
                                "conf": {
                                    "asyncFuncTimeout": 1000,
                                    "description": "Pipeline, generated from Kalipso query",
                                    "functions": [
                                        {
                                            "canFullyPushToFederated": true,
                                            "conf": {},
                                            "description": "dataset=\"cribl_search_sample\"",
                                            "disabled": false,
                                            "filter": "!(dataset == 'cribl_search_sample')",
                                            "final": false,
                                            "functionInstanceId": "root:0:2uw2",
                                            "id": "drop"
                                        },
                                        {
                                            "canFullyPushToFederated": false,
                                            "conf": {
                                                "aggregations": [
                                                    "count().as(cnt)"
                                                ],
                                                "cumulative": true,
                                                "flushOnInputClose": false,
                                                "groupbys": [
                                                    "srcaddr"
                                                ],
                                                "metricsMode": false,
                                                "preserveGroupBys": true,
                                                "printUndefineds": true,
                                                "searchAggMode": "Coordinated",
                                                "sufficientStatsOnly": false,
                                                "timeWindow": "1s"
                                            },
                                            "description": "summarize cnt=count() by srcaddr",
                                            "disabled": false,
                                            "filter": "true",
                                            "final": false,
                                            "functionInstanceId": "root:1:tTTC",
                                            "id": "aggregation"
                                        },
                                        {
                                            "canFullyPushToFederated": true,
                                            "conf": {
                                                "keep": [
                                                    "cnt",
                                                    "cnt.*",
                                                    "srcaddr",
                                                    "srcaddr.*"
                                                ],
                                                "printUndefineds": true,
                                                "remove": [
                                                    "*"
                                                ]
                                            },
                                            "description": "summarize cnt=count() by srcaddr",
                                            "disabled": false,
                                            "filter": "true",
                                            "final": false,
                                            "functionInstanceId": "root:3:uDgk",
                                            "id": "eval"
                                        }
                                    ]
                                },
                                "id": "root"
                            },
                            "Coordinated": {
                                ...
                            },
                            "Federated": {
                                ...
                            }
                        },
                        "referencedColumnPaths": [
                            [
                                "cnt"
                            ],
                            [
                                "srcaddr"
                            ]
                        ],
                        "searchTerms": [],
                        "useFormattedVisualization": true
                    },
                    "searchVersionByDatasetId": {},
                    "status": "new",
                    "subQueryText": "dataset=\"cribl_search_sample\" | summarize cnt=count() by srcaddr"
                }
            ],
            "status": "queued",
            "timeCreated": 1777447149939,
            "type": "standard",
            "usageGroupId": "default",
            "user": "EXAMPLECLIENTID0000000000000000@clients",
            "userDetails": {
                "apiCredential": {
                    "clientId": "EXAMPLECLIENTID0000000000000000@clients",
                    "createdBy": "example.user@example.com",
                    "name": "example.user@example.com"
                },
                "displayUsername": "example.user@example.com",
                "email": "example.user@example.com",
                "roles": [
                    "search_user",
                    "org_user",
                    "ws_user"
                ],
                "ssoGroups": [],
                "type": "apiCredential",
                "username": "EXAMPLECLIENTID0000000000000000@clients"
            }
        }
    }
}
```

#### Human Readable Output

>### Search Job Created
>
>|User|ID|Is Private|Type|Status|
>|---|---|---|---|---|
>| EXAMPLECLIENTID0000000000000000@clients | 1777447149939.xPWbOm | true | standard | queued |

### cribl-search-job-list

***
Retrieves a list of search jobs or details of a specific search job.

#### Base Command

`cribl-search-job-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | The unique identifier of a specific search job to retrieve. | Optional |
| limit | The maximum number of results to return. Default is 10. | Optional |
| all_results | Whether to return all results. If true, overrides the limit argument. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cribl.SearchJob.id | String | Unique identifier of the search job. |
| Cribl.SearchJob.user | String | User identifier \(client ID\) that created the job. |
| Cribl.SearchJob.displayUsername | String | Display name of the user who created the job. |
| Cribl.SearchJob.group | String | Search group the job belongs to. |
| Cribl.SearchJob.query | String | The search query string executed by the job. |
| Cribl.SearchJob.status | String | Current status of the search job \(e.g., queued, running, completed\). |
| Cribl.SearchJob.timeCreated | Number | Epoch \(ms\) when the search job was created. |
| Cribl.SearchJob.timeStarted | Number | Epoch \(ms\) when the search job started executing. |
| Cribl.SearchJob.timeCompleted | Number | Epoch \(ms\) when the search job completed. |
| Cribl.SearchJob.type | String | Type of search job \(e.g., standard, dashboard\). |
| Cribl.SearchJob.isPrivate | Boolean | Whether the search job is marked private. |
| Cribl.SearchJob.accelerated | Boolean | Whether the search job uses acceleration. |
| Cribl.SearchJob.earliest | String | Earliest time boundary for the search \(relative time string or epoch seconds\). |
| Cribl.SearchJob.earliestEpoch | Number | Resolved earliest time boundary in epoch milliseconds. |
| Cribl.SearchJob.latest | String | Latest time boundary for the search \(relative time string or epoch seconds\). |
| Cribl.SearchJob.latestEpoch | Number | Resolved latest time boundary in epoch milliseconds. |
| Cribl.SearchJob.cpuMetrics | Object | CPU usage metrics for the executed job \(billable seconds, per-executor breakdown, totals\). |
| Cribl.SearchJob.compatibilityChecks | Object | Compatibility check flags evaluated for the job. |
| Cribl.SearchJob.metadata | Object | Metadata about the query \(datasets, providers, operators, functions, etc.\). |
| Cribl.SearchJob.setOptions | Object | Additional search options provided when creating the job. |
| Cribl.SearchJob.stages | Unknown | Stages of the search job's execution plan, including per-stage cache status and search config. |

#### Command example

```!cribl-search-job-list limit=3```

#### Context Example

```json
{
    "Cribl": {
        "SearchJob": [
            {
                "accelerated": false,
                "compatibilityChecks": {
                    "datatypes": false
                },
                "cpuMetrics": {
                    "billableCPUSeconds": 24.78200000000004,
                    "executorsCPUSeconds": {
                        "23ywr3HV": 0.621,
                        "2C3c5u1h": 0.619,
                        "2G7pjwPk": 0.6,
                        "COORDINATOR": 5.817,
                        ...
                    },
                    "totalCPUSeconds": 24.78200000000004,
                    "totalExecCPUSeconds": 24.78200000000004
                },
                "displayUsername": "example.user@example.com",
                "earliest": "-24h",
                "earliestEpoch": 1777121543198,
                "group": "default_search",
                "id": "1777207943198.pb0ZZ0",
                "isPrivate": true,
                "latest": "now",
                "latestEpoch": 1777207943198,
                "metadata": {
                    "arguments": {},
                    "cloudProvider": "aws",
                    "computeTypes": {
                        "v1": 1
                    },
                    "datasets": {
                        "cribl_search_sample": 1
                    },
                    "functions": {},
                    "operators": {
                        "dataset=\"cribl_search_sample\"": 1,
                        "project": 1,
                        "take": 1
                    },
                    "providerTypes": {
                        "s3": 1
                    },
                    "providers": {
                        "cribl_s3sample_provider": 1
                    }
                },
                "query": "dataset=\"cribl_search_sample\" | project method, source, status, url | take 5",
                "setOptions": {},
                "stages": [
                    {
                        "cacheStatusByDatasetId": {
                            "cribl_search_sample": {
                                "cacheStatus": "miss",
                                "computeType": "v1",
                                "reason": "Not a Lake Dataset",
                                "usedCache": false
                            }
                        },
                        "dependencies": [],
                        "filter": "(dataset == 'cribl_search_sample')",
                        "id": "root",
                        "resolvedDatasetIds": [
                            "cribl_search_sample"
                        ],
                        "searchConfig": {
                            "canComputeMetadataDistributively": false,
                            "datasets": [
                                "cribl_search_sample"
                            ],
                            "hasSendOperator": false,
                            "logicalPlans": {
                                "Combined": {
                                    "root:0:HEER": [
                                        {
                                            "condition": {
                                                "caseSensitive": false,
                                                "lhs": {
                                                    "columnPath": [
                                                        "dataset"
                                                    ],
                                                    "type": "identifier"
                                                },
                                                "operator": "==",
                                                "rhs": {
                                                    "literal": "cribl_search_sample",
                                                    "type": "literal"
                                                },
                                                "type": "binaryOperation"
                                            },
                                            "type": "filter"
                                        }
                                    ],
                                    "root:1:UBPo": [
                                        {
                                            "add": [
                                                {
                                                    "columnPath": [
                                                        "method"
                                                    ],
                                                    "type": "identifier"
                                                },
                                                {
                                                    "columnPath": [
                                                        "source"
                                                    ],
                                                    "type": "identifier"
                                                },
                                                {
                                                    "columnPath": [
                                                        "status"
                                                    ],
                                                    "type": "identifier"
                                                },
                                                {
                                                    "columnPath": [
                                                        "url"
                                                    ],
                                                    "type": "identifier"
                                                }
                                            ],
                                            "removeOthers": true,
                                            "type": "project"
                                        }
                                    ],
                                    "root:3:Xm06": [
                                        {
                                            "limit": 5,
                                            "type": "limit"
                                        }
                                    ]
                                },
                                "Coordinated": {
                                    ...
                                },
                                "Federated": {
                                    ...
                                }
                            },
                            "orderedFieldNames": [
                                "method",
                                "source",
                                "status",
                                "url"
                            ],
                            "pipelines": {
                                "Combined": {
                                    "conf": {
                                        "asyncFuncTimeout": 1000,
                                        "description": "Pipeline, generated from Kalipso query",
                                        "functions": [
                                            {
                                                "canFullyPushToFederated": true,
                                                "conf": {},
                                                "description": "dataset=\"cribl_search_sample\"",
                                                "disabled": false,
                                                "filter": "!(dataset == 'cribl_search_sample')",
                                                "final": false,
                                                "functionInstanceId": "root:0:HEER",
                                                "id": "drop"
                                            },
                                            {
                                                "canFullyPushToFederated": false,
                                                "conf": {
                                                    "limit": 5
                                                },
                                                "description": "take 5",
                                                "disabled": false,
                                                "filter": "true",
                                                "final": false,
                                                "functionInstanceId": "root:3:Xm06",
                                                "id": "limit"
                                            },
                                            {
                                                "canFullyPushToFederated": true,
                                                "conf": {
                                                    "keep": [
                                                        "method",
                                                        "method.*",
                                                        "source",
                                                        "source.*",
                                                        "status",
                                                        "status.*",
                                                        "url",
                                                        "url.*"
                                                    ],
                                                    "printUndefineds": true,
                                                    "remove": [
                                                        "*"
                                                    ]
                                                },
                                                "description": "project method, source, status, url",
                                                "disabled": false,
                                                "filter": "true",
                                                "final": false,
                                                "functionInstanceId": "root:1:UBPo",
                                                "id": "eval"
                                            }
                                        ]
                                    },
                                    "id": "root"
                                },
                                "Coordinated": {
                                    ...
                                },
                                "Federated": {
                                    ...
                                }
                            },
                            "referencedColumnPaths": [
                                [
                                    "method"
                                ],
                                [
                                    "source"
                                ],
                                [
                                    "status"
                                ],
                                [
                                    "url"
                                ]
                            ],
                            "searchTerms": [],
                            "useFormattedVisualization": true
                        },
                        "searchVersionByDatasetId": {},
                        "status": "completed",
                        "subQueryText": "dataset=\"cribl_search_sample\" | project method, source, status, url | take 5"
                    }
                ],
                "status": "completed",
                "timeCompleted": 1777207949675,
                "timeCreated": 1777207943198,
                "timeStarted": 1777207943675,
                "type": "dashboard",
                "user": "EXAMPLECLIENTID0000000000000000@clients"
            },
            ...
        ]
    }
}
```

#### Human Readable Output

>### Search Jobs List
>
>|User|ID|Is Private|Type|Status|
>|---|---|---|---|---|
>| EXAMPLECLIENTID0000000000000000@clients | 1777207943198.pb0ZZ0 | true | dashboard | completed |
>| EXAMPLECLIENTID0000000000000000@clients | 1777208015306.F0hxMo | true | dashboard | completed |
>| EXAMPLECLIENTID0000000000000000@clients | 1777208286161.tTkDeJ | true | dashboard | completed |

### cribl-search-job-update

***
Updates a search job's status or privacy setting. At least one of status or is_private must be provided.

#### Base Command

`cribl-search-job-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | The unique identifier of the search job to update. | Required |
| status | The new status for the search job (e.g., completed, canceled). | Optional |
| is_private | Whether the search job should be private. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cribl.SearchJob.id | String | Unique identifier of the search job. |
| Cribl.SearchJob.user | String | User identifier \(client ID\) that created the job. |
| Cribl.SearchJob.displayUsername | String | Display name of the user who created the job. |
| Cribl.SearchJob.group | String | Search group the job belongs to. |
| Cribl.SearchJob.query | String | The search query string executed by the job. |
| Cribl.SearchJob.status | String | Current status of the search job \(e.g., queued, running, completed\). |
| Cribl.SearchJob.timeCreated | Number | Epoch \(ms\) when the search job was created. |
| Cribl.SearchJob.timeStarted | Number | Epoch \(ms\) when the search job started executing. |
| Cribl.SearchJob.timeCompleted | Number | Epoch \(ms\) when the search job completed. |
| Cribl.SearchJob.type | String | Type of search job \(e.g., standard, dashboard\). |
| Cribl.SearchJob.isPrivate | Boolean | Whether the search job is marked private. |
| Cribl.SearchJob.accelerated | Boolean | Whether the search job uses acceleration. |
| Cribl.SearchJob.earliest | String | Earliest time boundary for the search \(relative time string or epoch seconds\). |
| Cribl.SearchJob.earliestEpoch | Number | Resolved earliest time boundary in epoch milliseconds. |
| Cribl.SearchJob.latest | String | Latest time boundary for the search \(relative time string or epoch seconds\). |
| Cribl.SearchJob.latestEpoch | Number | Resolved latest time boundary in epoch milliseconds. |
| Cribl.SearchJob.compatibilityChecks | Object | Compatibility check flags evaluated for the job. |
| Cribl.SearchJob.metadata | Object | Metadata about the query \(datasets, providers, operators, functions, etc.\). |
| Cribl.SearchJob.setOptions | Object | Additional search options provided when creating the job. |
| Cribl.SearchJob.stages | Unknown | Stages of the search job's execution plan, including per-stage cache status and search config. |
| Cribl.SearchJob.userDetails | Object | Details about the user/credential that created the job. |
| Cribl.SearchJob.userDetails.email | String | Email address of the user who created the job. |
| Cribl.SearchJob.userDetails.username | String | Username of the user \(or client ID, for API-credential users\) who created the job. |
| Cribl.SearchJob.userDetails.displayUsername | String | Display name of the user who created the job. |
| Cribl.SearchJob.userDetails.type | String | Type of user identity \(e.g., apiCredential, sso\). |
| Cribl.SearchJob.userDetails.roles | Unknown | Roles assigned to the user. |

#### Command example

```!cribl-search-job-update job_id="1777446985069.KSZQ5h" is_private=true```

#### Context Example

```json
{
    "Cribl": {
        "SearchJob": {
            "accelerated": false,
            "compatibilityChecks": {
                "datatypes": false
            },
            "displayUsername": "example.user@example.com",
            "earliest": "-1h",
            "earliestEpoch": 1777443385069,
            "group": "default_search",
            "id": "1777446985069.KSZQ5h",
            "isPrivate": true,
            "latest": "now",
            "latestEpoch": 1777446985069,
            "metadata": {
                "arguments": {},
                "cloudProvider": "aws",
                "computeTypes": {
                    "v1": 1
                },
                "datasets": {
                    "cribl_search_sample": 1
                },
                "functions": {
                    "count": 1
                },
                "operators": {
                    "dataset=\"cribl_search_sample\"": 1,
                    "summarize": 1
                },
                "providerTypes": {
                    "s3": 1
                },
                "providers": {
                    "cribl_s3sample_provider": 1
                }
            },
            "query": "dataset=\"cribl_search_sample\" | summarize cnt=count() by srcaddr",
            "setOptions": {},
            "stages": [
                {
                    "cacheStatusByDatasetId": {
                        "cribl_search_sample": {
                            "cacheStatus": "miss",
                            "computeType": "v1",
                            "reason": "Not a Lake Dataset",
                            "usedCache": false
                        }
                    },
                    "dependencies": [],
                    "filter": "(dataset == 'cribl_search_sample')",
                    "id": "root",
                    "resolvedDatasetIds": [
                        "cribl_search_sample"
                    ],
                    "searchConfig": {
                        "canComputeMetadataDistributively": false,
                        "datasets": [
                            "cribl_search_sample"
                        ],
                        "hasSendOperator": false,
                        "logicalPlans": {
                            "Combined": {
                                "root:0:R25N": [
                                    {
                                        "condition": {
                                            "caseSensitive": false,
                                            "lhs": {
                                                "columnPath": [
                                                    "dataset"
                                                ],
                                                "type": "identifier"
                                            },
                                            "operator": "==",
                                            "rhs": {
                                                "literal": "cribl_search_sample",
                                                "type": "literal"
                                            },
                                            "type": "binaryOperation"
                                        },
                                        "type": "filter"
                                    }
                                ],
                                "root:1:TFOw": [
                                    {
                                        "aggregates": [
                                            {
                                                "assignee": {
                                                    "columnPath": [
                                                        "cnt"
                                                    ],
                                                    "type": "identifier"
                                                },
                                                "operation": {
                                                    "functionType": "aggregation",
                                                    "name": "count",
                                                    "parameters": [],
                                                    "type": "function"
                                                },
                                                "type": "assign"
                                            }
                                        ],
                                        "aggregationType": "summarize",
                                        "canDistributeAggregation": false,
                                        "groupBy": [
                                            {
                                                "columnPath": [
                                                    "srcaddr"
                                                ],
                                                "type": "identifier"
                                            }
                                        ],
                                        "isPreviewableOperation": true,
                                        "location": "coordinated",
                                        "type": "aggregate"
                                    }
                                ],
                                "root:3:zikB": [
                                    {
                                        "type": "noop"
                                    }
                                ]
                            },
                            "Coordinated": {
                                ...
                            },
                            "Federated": {
                                ...
                            }
                        },
                        "orderedFieldNames": [
                            "srcaddr",
                            "cnt"
                        ],
                        "pipelines": {
                            "Combined": {
                                "conf": {
                                    "asyncFuncTimeout": 1000,
                                    "description": "Pipeline, generated from Kalipso query",
                                    "functions": [
                                        {
                                            "canFullyPushToFederated": true,
                                            "conf": {},
                                            "description": "dataset=\"cribl_search_sample\"",
                                            "disabled": false,
                                            "filter": "!(dataset == 'cribl_search_sample')",
                                            "final": false,
                                            "functionInstanceId": "root:0:R25N",
                                            "id": "drop"
                                        },
                                        {
                                            "canFullyPushToFederated": false,
                                            "conf": {
                                                "aggregations": [
                                                    "count().as(cnt)"
                                                ],
                                                "cumulative": true,
                                                "flushOnInputClose": false,
                                                "groupbys": [
                                                    "srcaddr"
                                                ],
                                                "metricsMode": false,
                                                "preserveGroupBys": true,
                                                "printUndefineds": true,
                                                "searchAggMode": "Coordinated",
                                                "sufficientStatsOnly": false,
                                                "timeWindow": "1s"
                                            },
                                            "description": "summarize cnt=count() by srcaddr",
                                            "disabled": false,
                                            "filter": "true",
                                            "final": false,
                                            "functionInstanceId": "root:1:TFOw",
                                            "id": "aggregation"
                                        },
                                        {
                                            "canFullyPushToFederated": true,
                                            "conf": {
                                                "keep": [
                                                    "cnt",
                                                    "cnt.*",
                                                    "srcaddr",
                                                    "srcaddr.*"
                                                ],
                                                "printUndefineds": true,
                                                "remove": [
                                                    "*"
                                                ]
                                            },
                                            "description": "summarize cnt=count() by srcaddr",
                                            "disabled": false,
                                            "filter": "true",
                                            "final": false,
                                            "functionInstanceId": "root:3:zikB",
                                            "id": "eval"
                                        }
                                    ]
                                },
                                "id": "root"
                            },
                            "Coordinated": {
                                ...
                            },
                            "Federated": {
                                ...
                            }
                        },
                        "referencedColumnPaths": [
                            [
                                "cnt"
                            ],
                            [
                                "srcaddr"
                            ]
                        ],
                        "searchTerms": [],
                        "useFormattedVisualization": true
                    },
                    "searchVersionByDatasetId": {},
                    "status": "completed",
                    "subQueryText": "dataset=\"cribl_search_sample\" | summarize cnt=count() by srcaddr"
                }
            ],
            "status": "completed",
            "timeCompleted": 1777446992662,
            "timeCreated": 1777446985069,
            "timeStarted": 1777446985598,
            "type": "standard",
            "user": "EXAMPLECLIENTID0000000000000000@clients",
            "userDetails": {
                "apiCredential": {
                    "clientId": "EXAMPLECLIENTID0000000000000000@clients",
                    "createdBy": "example.user@example.com",
                    "name": "example.user@example.com"
                },
                "displayUsername": "example.user@example.com",
                "email": "example.user@example.com",
                "roles": [
                    "search_user",
                    "org_user",
                    "ws_user"
                ],
                "ssoGroups": [],
                "type": "apiCredential",
                "username": "EXAMPLECLIENTID0000000000000000@clients"
            }
        }
    }
}
```

#### Human Readable Output

>The job 1777446985069.KSZQ5h has been successfully updated.

### cribl-search-job-delete

***
Deletes a specific search job.

#### Base Command

`cribl-search-job-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | The unique identifier of the search job to delete. | Required |

#### Context Output

There is no context output for this command.

#### Command example

```!cribl-search-job-delete job_id="1777446985069.KSZQ5h"```

#### Human Readable Output

>The job 1777446985069.KSZQ5h has been successfully deleted.

### cribl-search-dataset-list

***
Retrieves a list of available datasets or details of a specific dataset.

#### Base Command

`cribl-search-dataset-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| dataset_id | The unique identifier of a specific dataset to retrieve. | Optional |
| limit | The maximum number of results to return. Default is 10. | Optional |
| all_results | Whether to return all results. If true, overrides the limit argument. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cribl.SearchDataset.id | String | The unique identifier of the dataset. |
| Cribl.SearchDataset.type | String | The dataset provider type \(for example, s3, azure_blob, gcs\). |
| Cribl.SearchDataset.provider | String | The identifier of the provider configuration backing the dataset. |
| Cribl.SearchDataset.region | String | The cloud region where the dataset's underlying storage resides \(when applicable\). |
| Cribl.SearchDataset.bucket | String | The bucket/path template that locates the dataset's underlying objects. |
| Cribl.SearchDataset.description | String | The human-readable description of the dataset. |
| Cribl.SearchDataset.filter | String | The filter expression applied to events from the dataset; defaults to "true" \(passes all events\). |
| Cribl.SearchDataset.tags | Unknown | The tags assigned to the dataset \(string or array of strings\). |
| Cribl.SearchDataset.breakerRulesets | Unknown | The event breaker rulesets associated with the dataset. |
| Cribl.SearchDataset.storageClasses | Unknown | The storage classes the dataset is configured to read from. |
| Cribl.SearchDataset.staleChannelFlushMs | Number | The time in milliseconds after which a stale channel is flushed during ingestion. |

#### Command example

```!cribl-search-dataset-list limit=3```

#### Context Example

```json
{
    "Cribl": {
        "SearchDataset": {
            "breakerRulesets": [
                "AWS Datatypes",
                "Apache Datatypes",
                "Syslog Datatypes",
                "Cribl Search",
                "Microsoft Windows Datatypes",
                "Azure Datatypes",
                "Microsoft O365 Datatypes",
                "Microsoft Graph API Datatypes"
            ],
            "bucket": "cribl-search-example/data/${dataSource}/${_time:%Y}/${_time:%m}/${_time:%d}/${_time:%H}",
            "description": "Search Cribl provided public sample data",
            "filter": "true",
            "id": "cribl_search_sample",
            "provider": "cribl_s3sample_provider",
            "region": "us-west-2",
            "staleChannelFlushMs": 10000,
            "storageClasses": [
                "STANDARD",
                "INTELLIGEN",
                "STANDARD_I",
                "ONEZONE_IA",
                "GLACIER_IR",
                "REDUCED_RE",
                "_RESTORED"
            ],
            "tags": "cribl:default",
            "type": "s3"
        }
    }
}
```

#### Human Readable Output

>### Datasets List
>
>|ID|Provider|Type|Region|
>|---|---|---|---|
>| cribl_search_sample | cribl_s3sample_provider | s3 | us-west-2 |

### cribl-saved-search-list

***
Retrieves a list of saved searches or details of a specific saved search.

#### Base Command

`cribl-saved-search-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search_id | The unique identifier of a specific saved search to retrieve. | Optional |
| limit | The maximum number of results to return. Default is 10. | Optional |
| all_results | Whether to return all results. If true, overrides the limit argument. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cribl.SavedSearch.id | String | The unique identifier of the saved search. |
| Cribl.SavedSearch.name | String | The display name of the saved search. |
| Cribl.SavedSearch.query | String | The search query string defined by the saved search. |

#### Command example

```!cribl-saved-search-list limit=3```

#### Context Example

```json
{
    "Cribl": {
        "SavedSearch": [
            {
                "description": "Searches finished in the last 1h",
                "earliest": "-1h",
                "id": "cribl_search_finished_1h",
                "latest": "now",
                "lib": "cribl",
                "name": "cribl_search_finished_1h",
                "query": "cribl dataset=\"cribl_internal_logs\" source=*searches.log message=\"search finished\" | summarize count(), elapsedMS=sum(stats.elapsedMs), eventsFound=sum(stats.eventsFound) by user=coalesce(stats.userDisplayName, stats.user)"
            },
            {
                "description": "Searches started in the last 1h",
                "earliest": "-1h",
                "id": "cribl_search_started_1h",
                "latest": "now",
                "lib": "cribl",
                "name": "cribl_search_started_1h",
                "query": "cribl dataset=\"cribl_internal_logs\" source=*searches.log message=\"search started\" | summarize count() by user=coalesce(stats.userDisplayName, stats.user)"
            }
        ]
    }
}
```

#### Human Readable Output

>### Saved Searches List
>
>|ID|Description|Name|Query|
>|---|---|---|---|
>| cribl_search_finished_1h | Searches finished in the last 1h | cribl_search_finished_1h | cribl dataset="cribl_internal_logs" source=*searches.log message="search finished" \| summarize count(), elapsedMS=sum(stats.elapsedMs), eventsFound=sum(stats.eventsFound) by user=coalesce(stats.userDisplayName, stats.user) |
>| cribl_search_started_1h | Searches started in the last 1h | cribl_search_started_1h | cribl dataset="cribl_internal_logs" source=*searches.log message="search started" \| summarize count() by user=coalesce(stats.userDisplayName, stats.user) |
