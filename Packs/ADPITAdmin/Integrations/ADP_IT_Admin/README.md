ADP integration to import ADP user data
This integration was integrated and tested with version xx of ADP IT Admin
## Configure ADP IT Admin on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for ADP IT Admin.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| adp_credentials | Client Id | True |
| cert_file | Certficate and Key for Mutual TLS | False |
| proxy | Use system proxy settings | False |
| insecure | Trust any certificate \(not secure\) | False |
| feed | Fetch indicators | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### adp-get-worker
***
Gets an ADP User


#### Base Command

`adp-get-worker`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| associateOID | Associate OID | Required |


#### Context Output

There is no context output for this command.

#### Command Example
``` !adp-get-worker associateOID=G3VSE2R6 ```

#### Context Example
```
{
    ""confirmMessage"": null,
    ""meta"": null,
    ""workers"": [
        {
            ""associateOID"": ""G3VSE2R6"",
            ""businessCommunication"": {
                ""emails"": [
                    {
                        ""emailUri"": ""test@paloaltonetworks.com"",
                        ""itemID"": ""Business"",
                        ""nameCode"": {
                            ""codeValue"": ""Work E-mail"",
                            ""shortName"": ""Work E-mail""
                        }
                    }
                ]
            },
            ""person"": {
                ""birthDate"": ""0000-00-00"",
                ""communication"": {
                    ""mobiles"": [
                        {
                            ""access"": ""1"",
                            ""areaDialing"": ""408"",
                            ""countryDialing"": ""1"",
                            ""dialNumber"": ""9999999"",
                            ""formattedNumber"": ""(408) 999-9999"",
                            ""itemID"": ""874171873_5123"",
                            ""nameCode"": {
                                ""codeValue"": ""Personal Cell"",
                                ""shortName"": ""Personal Cell""
                            }
                        }
                    ]
                },
                ""genderCode"": {
                    ""codeValue"": ""F"",
                    ""longName"": ""Female"",
                    ""shortName"": ""Female""
                },
                ""governmentIDs"": [
                    {
                        ""countryCode"": ""US"",
                        ""idValue"": ""XXX-XX-XXXX"",
                        ""itemID"": ""fgfgfgsd"",
                        ""nameCode"": {
                            ""codeValue"": ""SSN"",
                            ""longName"": ""Social Security Number""
                        }
                    }
                ],
                ""legalAddress"": {
                    ""cityName"": ""San Jose"",
                    ""countryCode"": ""US"",
                    ""countrySubdivisionLevel1"": {
                        ""codeValue"": ""CA"",
                        ""shortName"": ""California"",
                        ""subdivisionType"": ""StateTerritory""
                    },
                    ""countrySubdivisionLevel2"": {
                        ""codeValue"": ""USA"",
                        ""shortName"": ""USA"",
                        ""subdivisionType"": ""County""
                    },
                    ""lineOne"": ""1111 Highway Drive"",
                    ""nameCode"": {
                        ""codeValue"": ""Personal Address 1"",
                        ""longName"": ""Personal Address 1"",
                        ""shortName"": ""Personal Address 1""
                    },
                    ""postalCode"": ""95138""
                },
                ""legalName"": {
                    ""familyName1"": ""Test Last Name"",
                    ""formattedName"": ""Test Last Name, FirstName"",
                    ""givenName"": ""FirstName"",
                    ""nickName"": ""FirstName""
                },
                ""maritalStatusCode"": {
                    ""codeValue"": ""M"",
                    ""effectiveDate"": ""2015-04-20"",
                    ""shortName"": ""Married""
                },
                ""preferredName"": {
                    ""givenName"": ""FirstName""
                }
            },
            ""workAssignments"": [
                {
                    ""actualStartDate"": ""2000-04-20"",
                    ""assignedOrganizationalUnits"": [
                        {
                            ""nameCode"": {
                                ""codeValue"": ""PANW"",
                                ""longName"": ""Palo Alto Networks, Inc.""
                            },
                            ""typeCode"": {
                                ""codeValue"": ""Business Unit"",
                                ""shortName"": ""Business Unit""
                            }
                        },
                        {
                            ""nameCode"": {
                                ""codeValue"": ""1234"",
                                ""shortName"": ""IT""
                            },
                            ""typeCode"": {
                                ""codeValue"": ""Department"",
                                ""shortName"": ""Department""
                            }
                        },
                        {
                            ""nameCode"": {
                                ""codeValue"": ""1234"",
                                ""shortName"": ""IT""
                            },
                            ""typeCode"": {
                                ""codeValue"": ""Cost Number"",
                                ""shortName"": ""Cost Number""
                            }
                        }
                    ],
                    ""assignmentStatus"": {
                        ""statusCode"": {
                            ""codeValue"": ""A"",
                            ""longName"": ""Active"",
                            ""shortName"": ""Active""
                        }
                    },
                    ""hireDate"": ""2000-04-20"",
                    ""homeOrganizationalUnits"": [
                        {
                            ""nameCode"": {
                                ""codeValue"": ""PANW"",
                                ""longName"": ""Palo Alto Networks, Inc.""
                            },
                            ""typeCode"": {
                                ""codeValue"": ""Business Unit"",
                                ""shortName"": ""Business Unit""
                            }
                        },
                        {
                            ""nameCode"": {
                                ""codeValue"": ""1234"",
                                ""shortName"": ""IT""
                            },
                            ""typeCode"": {
                                ""codeValue"": ""Department"",
                                ""shortName"": ""Department""
                            }
                        },
                        {
                            ""nameCode"": {
                                ""codeValue"": ""1234"",
                                ""shortName"": ""IT""
                            },
                            ""typeCode"": {
                                ""codeValue"": ""Cost Number"",
                                ""shortName"": ""Cost Number""
                            }
                        }
                    ],
                    ""homeWorkLocation"": {
                        ""nameCode"": {
                            ""codeValue"": ""CA"",
                            ""shortName"": ""California""
                        }
                    },
                    ""industryClassifications"": [
                        {
                            ""classificationCode"": {
                                ""codeValue"": ""1234"",
                                ""longName"": ""Clerical Office Employees""
                            },
                            ""nameCode"": {
                                ""codeValue"": ""ABCS"",
                                ""shortName"": ""ABCS""
                            }
                        }
                    ],
                    ""itemID"": ""7dfg9496N"",
                    ""managementPositionIndicator"": false,
                    ""occupationalClassifications"": [
                        {
                            ""classificationCode"": {
                                ""codeValue"": ""8810"",
                                ""longName"": ""Clerical Office Employees""
                            },
                            ""nameCode"": {
                                ""codeValue"": ""ABCS"",
                                ""shortName"": ""ABCS""
                            }
                        }
                    ],
                    ""payrollFileNumber"": ""123456"",
                    ""payrollGroupCode"": ""DFV"",
                    ""payrollProcessingStatusCode"": {
                        ""shortName"": ""Paid""
                    },
                    ""payrollScheduleGroupID"": ""Use Period End Date 1 on checks"",
                    ""positionID"": ""12345"",
                    ""primaryIndicator"": true,
                    ""wageLawCoverage"": {
                        ""coverageCode"": {
                            ""codeValue"": ""E"",
                            ""shortName"": ""Exempt""
                        },
                        ""wageLawNameCode"": {
                            ""codeValue"": ""FLSA"",
                            ""longName"": ""Fair Labor Standards Act""
                        }
                    },
                    ""workerTypeCode"": {
                        ""codeValue"": ""F"",
                        ""shortName"": ""Regular""
                    }
                }
            ],
            ""workerDates"": {
                ""originalHireDate"": ""2000-04-20""
            },
            ""workerID"": {
                ""idValue"": ""987654""
            },
            ""workerStatus"": {
                ""statusCode"": {
                    ""codeValue"": ""Active""
                }
            }
        }
    ]
}
```

#### Human Readable Output



### adp-get-all-workers-trigger-async
***
This triggers an asynchronous Worker API request to ADP. It returns a URI and retryafter in the response context. Call the next command after waiting for "ADP.RetryAfter" seconds


#### Base Command

`adp-get-all-workers-trigger-async`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ADP.WorkersURI | String | The Link will return the records you requested 1,000 at a time |
| ADP.RetryAfter | Number | The number of seconds to wait before making the call to "ADP.WorkersURI" |


#### Command Example
```!adp-get-all-workers-trigger-async```

#### Context Example
```
"""ADP"": {
        ""RetryAfter"": ""3999"",
        ""WorkersURI"": ""/core/v1/operations/workerInformationManagement/hr.v2.workers/9200029094106%5F1?$select=processingStatus""
    }"
```

#### Human Readable Output



### adp-get-all-workers
***
This uses the ADP Async method. Call the command "adp-get-all-workers-trigger-async" before calling this command, to get the workersURI


#### Base Command

`adp-get-all-workers`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| workersURI | ADP Workers URI received from the command "adp-get-all-workers-trigger-async" | Required |


#### Context Output

There is no context output for this command.

#### Command Example
```!adp-get-all-workers workersURI="/core/v1/operations/workerInformationManagement/hr.v2.workers/9200029094106%5F1?$select=processingStatus"```

#### Context Example
```
{
    ""confirmMessage"": null,
    ""meta"": null,
    ""workers"": [
        {
            ""associateOID"": ""G3VSE2R6"",
            ""businessCommunication"": {
                ""emails"": [
                    {
                        ""emailUri"": ""test@paloaltonetworks.com"",
                        ""itemID"": ""Business"",
                        ""nameCode"": {
                            ""codeValue"": ""Work E-mail"",
                            ""shortName"": ""Work E-mail""
                        }
                    }
                ]
            },
            ""person"": {
                ""birthDate"": ""0000-00-00"",
                ""communication"": {
                    ""mobiles"": [
                        {
                            ""access"": ""1"",
                            ""areaDialing"": ""408"",
                            ""countryDialing"": ""1"",
                            ""dialNumber"": ""9999999"",
                            ""formattedNumber"": ""(408) 999-9999"",
                            ""itemID"": ""874171873_5123"",
                            ""nameCode"": {
                                ""codeValue"": ""Personal Cell"",
                                ""shortName"": ""Personal Cell""
                            }
                        }
                    ]
                },
                ""genderCode"": {
                    ""codeValue"": ""F"",
                    ""longName"": ""Female"",
                    ""shortName"": ""Female""
                },
                ""governmentIDs"": [
                    {
                        ""countryCode"": ""US"",
                        ""idValue"": ""XXX-XX-XXXX"",
                        ""itemID"": ""fgfgfgsd"",
                        ""nameCode"": {
                            ""codeValue"": ""SSN"",
                            ""longName"": ""Social Security Number""
                        }
                    }
                ],
                ""legalAddress"": {
                    ""cityName"": ""San Jose"",
                    ""countryCode"": ""US"",
                    ""countrySubdivisionLevel1"": {
                        ""codeValue"": ""CA"",
                        ""shortName"": ""California"",
                        ""subdivisionType"": ""StateTerritory""
                    },
                    ""countrySubdivisionLevel2"": {
                        ""codeValue"": ""USA"",
                        ""shortName"": ""USA"",
                        ""subdivisionType"": ""County""
                    },
                    ""lineOne"": ""1111 Highway Drive"",
                    ""nameCode"": {
                        ""codeValue"": ""Personal Address 1"",
                        ""longName"": ""Personal Address 1"",
                        ""shortName"": ""Personal Address 1""
                    },
                    ""postalCode"": ""95138""
                },
                ""legalName"": {
                    ""familyName1"": ""Test Last Name"",
                    ""formattedName"": ""Test Last Name, FirstName"",
                    ""givenName"": ""FirstName"",
                    ""nickName"": ""FirstName""
                },
                ""maritalStatusCode"": {
                    ""codeValue"": ""M"",
                    ""effectiveDate"": ""2015-04-20"",
                    ""shortName"": ""Married""
                },
                ""preferredName"": {
                    ""givenName"": ""FirstName""
                }
            },
            ""workAssignments"": [
                {
                    ""actualStartDate"": ""2000-04-20"",
                    ""assignedOrganizationalUnits"": [
                        {
                            ""nameCode"": {
                                ""codeValue"": ""PANW"",
                                ""longName"": ""Palo Alto Networks, Inc.""
                            },
                            ""typeCode"": {
                                ""codeValue"": ""Business Unit"",
                                ""shortName"": ""Business Unit""
                            }
                        },
                        {
                            ""nameCode"": {
                                ""codeValue"": ""1234"",
                                ""shortName"": ""IT""
                            },
                            ""typeCode"": {
                                ""codeValue"": ""Department"",
                                ""shortName"": ""Department""
                            }
                        },
                        {
                            ""nameCode"": {
                                ""codeValue"": ""1234"",
                                ""shortName"": ""IT""
                            },
                            ""typeCode"": {
                                ""codeValue"": ""Cost Number"",
                                ""shortName"": ""Cost Number""
                            }
                        }
                    ],
                    ""assignmentStatus"": {
                        ""statusCode"": {
                            ""codeValue"": ""A"",
                            ""longName"": ""Active"",
                            ""shortName"": ""Active""
                        }
                    },
                    ""hireDate"": ""2000-04-20"",
                    ""homeOrganizationalUnits"": [
                        {
                            ""nameCode"": {
                                ""codeValue"": ""PANW"",
                                ""longName"": ""Palo Alto Networks, Inc.""
                            },
                            ""typeCode"": {
                                ""codeValue"": ""Business Unit"",
                                ""shortName"": ""Business Unit""
                            }
                        },
                        {
                            ""nameCode"": {
                                ""codeValue"": ""1234"",
                                ""shortName"": ""IT""
                            },
                            ""typeCode"": {
                                ""codeValue"": ""Department"",
                                ""shortName"": ""Department""
                            }
                        },
                        {
                            ""nameCode"": {
                                ""codeValue"": ""1234"",
                                ""shortName"": ""IT""
                            },
                            ""typeCode"": {
                                ""codeValue"": ""Cost Number"",
                                ""shortName"": ""Cost Number""
                            }
                        }
                    ],
                    ""homeWorkLocation"": {
                        ""nameCode"": {
                            ""codeValue"": ""CA"",
                            ""shortName"": ""California""
                        }
                    },
                    ""industryClassifications"": [
                        {
                            ""classificationCode"": {
                                ""codeValue"": ""1234"",
                                ""longName"": ""Clerical Office Employees""
                            },
                            ""nameCode"": {
                                ""codeValue"": ""ABCS"",
                                ""shortName"": ""ABCS""
                            }
                        }
                    ],
                    ""itemID"": ""7dfg9496N"",
                    ""managementPositionIndicator"": false,
                    ""occupationalClassifications"": [
                        {
                            ""classificationCode"": {
                                ""codeValue"": ""8810"",
                                ""longName"": ""Clerical Office Employees""
                            },
                            ""nameCode"": {
                                ""codeValue"": ""ABCS"",
                                ""shortName"": ""ABCS""
                            }
                        }
                    ],
                    ""payrollFileNumber"": ""123456"",
                    ""payrollGroupCode"": ""DFV"",
                    ""payrollProcessingStatusCode"": {
                        ""shortName"": ""Paid""
                    },
                    ""payrollScheduleGroupID"": ""Use Period End Date 1 on checks"",
                    ""positionID"": ""12345"",
                    ""primaryIndicator"": true,
                    ""wageLawCoverage"": {
                        ""coverageCode"": {
                            ""codeValue"": ""E"",
                            ""shortName"": ""Exempt""
                        },
                        ""wageLawNameCode"": {
                            ""codeValue"": ""FLSA"",
                            ""longName"": ""Fair Labor Standards Act""
                        }
                    },
                    ""workerTypeCode"": {
                        ""codeValue"": ""F"",
                        ""shortName"": ""Regular""
                    }
                }
            ],
            ""workerDates"": {
                ""originalHireDate"": ""2000-04-20""
            },
            ""workerID"": {
                ""idValue"": ""987654""
            },
            ""workerStatus"": {
                ""statusCode"": {
                    ""codeValue"": ""Active""
                }
            }
        }
    ]
}
```

#### Human Readable Output



