CAMPAIGN_INCIDENT_CONTEXT = {
    "EmailCampaign": {
        "firstIncidentDate": "2021-11-21T14:00:07.425185+00:00",
        "incidents": [
            {
                "emailfrom": "examplesupport@example2.com",
                "emailfromdomain": "example.com",
                "id": "1",
                "name": "Verify your example account 798",
                "occurred": "2021-11-21T14:00:07.119800133Z",
                "recipients": [
                    "victim-test6@demistodev.onmicrosoft.com"
                ],
                "recipientsdomain": [
                    "onmicrosoft.com"
                ],
                "severity": 0,
                "similarity": 1,
                "status": 1
            },
            {
                "emailfrom": "examplesupport@example2.com",
                "emailfromdomain": "example2.com",
                "id": "2",
                "name": "Verify your example account 798",
                "occurred": "2021-11-21T14:59:01.690685509Z",
                "recipients": [
                    "victim-test1@demistodev.onmicrosoft.com"
                ],
                "recipientsdomain": [
                    "onmicrosoft.com"
                ],
                "severity": 0,
                "similarity": 0.9999999999999999,
                "status": 1
            },
            {
                "emailfrom": "examplesupport@example2.com",
                "emailfromdomain": "example.com",
                "id": "3",
                "name": "Verify your example account 798",
                "occurred": "2021-11-21T15:00:07.425185504Z",
                "recipients": [
                    "victim-test7@demistodev.onmicrosoft.com"
                ],
                "recipientsdomain": [
                    "onmicrosoft.com"
                ],
                "severity": 3,
                "similarity": 1,
                "status": 1
            }
        ],
        "indicators": [
            {
                "id": "1263",
                "value": "http://www.example.com"
            }
        ],
        "involvedIncidentsCount": 3,
        "isCampaignFound": True
    },
    "ExistingCampaignID": [
        "809"
    ]
}
NEW_INCIDENT_CONTEXT = {
    "EmailCampaign": {
        "firstIncidentDate": "2021-11-21T14:00:07.425185+00:00",
        "incidents": [
            {
                "emailfrom": "examplesupport@example2.com",
                "emailfromdomain": "example.com",
                "id": "5",
                "name": "Verify your example account 798",
                "occurred": "2021-11-21T15:01:07.119800133Z",
                "recipients": [
                    "victim-test6@demistodev.onmicrosoft.com"
                ],
                "recipientsdomain": [
                    "onmicrosoft.com"
                ],
                "severity": 0,
                "similarity": 1,
                "status": 1
            },
            {
                "emailfrom": "examplesupport@example2.com",
                "emailfromdomain": "example.com",
                "id": "1",
                "name": "Verify your example account 798",
                "occurred": "2021-11-21T14:00:07.119800133Z",
                "recipients": [
                    "victim-test6@demistodev.onmicrosoft.com"
                ],
                "recipientsdomain": [
                    "onmicrosoft.com"
                ],
                "severity": 0,
                "similarity": 0.99,
                "status": 1
            },
            {
                "emailfrom": "examplesupport@example2.com",
                "emailfromdomain": "example2.com",
                "id": "2",
                "name": "Verify your example account 798",
                "occurred": "2021-11-21T14:59:01.690685509Z",
                "recipients": [
                    "victim-test1@demistodev.onmicrosoft.com"
                ],
                "recipientsdomain": [
                    "onmicrosoft.com"
                ],
                "severity": 0,
                "similarity": 0.98,
                "status": 1
            },
            {
                "emailfrom": "examplesupport@example2.com",
                "emailfromdomain": "example.com",
                "id": "3",
                "name": "Verify your example account 798",
                "occurred": "2021-11-21T15:00:07.425185504Z",
                "recipients": [
                    "victim-test7@demistodev.onmicrosoft.com"
                ],
                "recipientsdomain": [
                    "onmicrosoft.com"
                ],
                "severity": 3,
                "similarity": 0.85,
                "status": 1
            }
        ],
        "indicators": [
            {
                "id": "1263",
                "value": "http://www.example.com"
            }
        ],
        "involvedIncidentsCount": 4,
        "isCampaignFound": True
    },
    "ExistingCampaignID": [
        "809"
    ]
}
NEW_INCIDENT_2_CONTEXT = {
    "EmailCampaign": {
        "firstIncidentDate": "2021-11-21T14:00:07.425185+00:00",
        "incidents": [
            {
                "emailfrom": "examplesupport@example2.com",
                "emailfromdomain": "example.com",
                "id": "4",
                "name": "Verify your example account 798",
                "occurred": "2021-11-21T16:00:00.119800133Z",
                "recipients": [
                    "victim-test6@demistodev.onmicrosoft.com"
                ],
                "recipientsdomain": [
                    "onmicrosoft.com"
                ],
                "severity": 0,
                "similarity": 1,
                "status": 1
            },
            {
                "emailfrom": "examplesupport@example2.com",
                "emailfromdomain": "example.com",
                "id": "1",
                "name": "Verify your example account 798",
                "occurred": "2021-11-21T14:00:07.119800133Z",
                "recipients": [
                    "victim-test6@demistodev.onmicrosoft.com"
                ],
                "recipientsdomain": [
                    "onmicrosoft.com"
                ],
                "severity": 0,
                "similarity": 0.98,
                "status": 1
            },
            {
                "emailfrom": "examplesupport@example2.com",
                "emailfromdomain": "example2.com",
                "id": "2",
                "name": "Verify your example account 798",
                "occurred": "2021-11-21T14:59:01.690685509Z",
                "recipients": [
                    "victim-test1@demistodev.onmicrosoft.com"
                ],
                "recipientsdomain": [
                    "onmicrosoft.com"
                ],
                "severity": 0,
                "similarity": 0.97,
                "status": 1
            },
            {
                "emailfrom": "examplesupport@example2.com",
                "emailfromdomain": "example.com",
                "id": "3",
                "name": "Verify your example account 798",
                "occurred": "2021-11-21T15:00:07.425185504Z",
                "recipients": [
                    "victim-test7@demistodev.onmicrosoft.com"
                ],
                "recipientsdomain": [
                    "onmicrosoft.com"
                ],
                "severity": 3,
                "similarity": 0.86,
                "status": 1
            }
        ],
        "indicators": [
            {
                "id": "1263",
                "value": "http://www.example.com"
            }
        ],
        "involvedIncidentsCount": 4,
        "isCampaignFound": True
    },
    "ExistingCampaignID": [
        "809"
    ]
}
OLD_INCIDENT_CONTEXT = {
    "EmailCampaign": {
        "firstIncidentDate": "2021-11-21T14:00:07.425185+00:00",
        "incidents": [
            {
                "emailfrom": "examplesupport@example2.com",
                "emailfromdomain": "example.com",
                "id": "1",
                "name": "Verify your example account 798",
                "occurred": "2021-11-21T14:00:07.119800133Z",
                "recipients": [
                    "victim-test6@demistodev.onmicrosoft.com"
                ],
                "recipientsdomain": [
                    "onmicrosoft.com"
                ],
                "severity": 0,
                "similarity": 1,
                "status": 1
            },
            {
                "emailfrom": "examplesupport@example2.com",
                "emailfromdomain": "example2.com",
                "id": "2",
                "name": "Verify your example account 798",
                "occurred": "2021-11-21T14:59:01.690685509Z",
                "recipients": [
                    "victim-test1@demistodev.onmicrosoft.com"
                ],
                "recipientsdomain": [
                    "onmicrosoft.com"
                ],
                "severity": 0,
                "similarity": 0.9999999999999999,
                "status": 1
            },
            {
                "emailfrom": "examplesupport@example2.com",
                "emailfromdomain": "example.com",
                "id": "3",
                "name": "Verify your example account 798",
                "occurred": "2021-11-21T15:00:07.425185504Z",
                "recipients": [
                    "victim-test7@demistodev.onmicrosoft.com"
                ],
                "recipientsdomain": [
                    "onmicrosoft.com"
                ],
                "severity": 3,
                "similarity": 1,
                "status": 1
            }
        ],
        "indicators": [
            {
                "id": "1263",
                "value": "http://www.example.com"
            }
        ],
        "involvedIncidentsCount": 3,
        "isCampaignFound": True
    },
    "ExistingCampaignID": [
        "809"
    ]
}
NEW_EMPTY_CAMPAIGN = {}
REAL_INCIDENT = {
"EmailCampaign": {
            "fieldsToDisplay": [
                "id",
                "name",
                "similarity",
                "emailfrom",
                "recipients",
                "severity",
                "status",
                "occurred"
            ],
            "firstIncidentDate": "2021-11-28T16:37:08.329879+00:00",
            "incidents": [
                {
                    "emailfrom": "paypalsupport@paypaI.com",
                    "emailfromdomain": "paypaI.com",
                    "id": "846",
                    "name": "Verify your PayPal account 838",
                    "occurred": "2021-11-28T16:37:08.71463319Z",
                    "recipients": [
                        "victim-test9@demistodev.onmicrosoft.com"
                    ],
                    "recipientsdomain": [
                        "onmicrosoft.com"
                    ],
                    "severity": 0,
                    "similarity": 1,
                    "status": 1
                },
                {
                    "emailfrom": "paypalsupport@paypaI.com",
                    "emailfromdomain": "paypaI.com",
                    "id": "839",
                    "name": "Verify your PayPal account 838",
                    "occurred": "2021-11-28T16:37:08.329879579Z",
                    "recipients": [
                        "victim-test5@demistodev.onmicrosoft.com"
                    ],
                    "recipientsdomain": [
                        "onmicrosoft.com"
                    ],
                    "severity": 0,
                    "similarity": 1.0000000000000002,
                    "status": 1
                },
                {
                    "emailfrom": "paypalsupport@paypaI.com",
                    "emailfromdomain": "paypaI.com",
                    "id": "841",
                    "name": "Verify your PayPal account 838",
                    "occurred": "2021-11-28T16:37:08.375906074Z",
                    "recipients": [
                        "victim-test4@demistodev.onmicrosoft.com"
                    ],
                    "recipientsdomain": [
                        "onmicrosoft.com"
                    ],
                    "severity": 0,
                    "similarity": 1.0000000000000002,
                    "status": 1
                },
                {
                    "emailfrom": "paypalsupport@paypaI.com",
                    "emailfromdomain": "paypaI.com",
                    "id": "842",
                    "name": "Verify your PayPal account 838",
                    "occurred": "2021-11-28T16:37:08.412540207Z",
                    "recipients": [
                        "victim-test8@demistodev.onmicrosoft.com"
                    ],
                    "recipientsdomain": [
                        "onmicrosoft.com"
                    ],
                    "severity": 0,
                    "similarity": 1.0000000000000002,
                    "status": 1
                },
                {
                    "emailfrom": "paypalsupport@paypaI.com",
                    "emailfromdomain": "paypaI.com",
                    "id": "843",
                    "name": "Verify your PayPal account 838",
                    "occurred": "2021-11-28T16:37:08.443743646Z",
                    "recipients": [
                        "victim-test3@demistodev.onmicrosoft.com"
                    ],
                    "recipientsdomain": [
                        "onmicrosoft.com"
                    ],
                    "severity": 0,
                    "similarity": 1.0000000000000002,
                    "status": 1
                },
                {
                    "emailfrom": "paypalsupport@paypaI.com",
                    "emailfromdomain": "paypaI.com",
                    "id": "845",
                    "name": "Verify your PayPal account 838",
                    "occurred": "2021-11-28T16:37:08.507298426Z",
                    "recipients": [
                        "victim-test7@demistodev.onmicrosoft.com"
                    ],
                    "recipientsdomain": [
                        "onmicrosoft.com"
                    ],
                    "severity": 0,
                    "similarity": 1.0000000000000002,
                    "status": 1
                },
                {
                    "emailfrom": "paypalsupport@paypaI.com",
                    "emailfromdomain": "paypaI.com",
                    "id": "840",
                    "name": "Verify your PayPal account 838",
                    "occurred": "2021-11-28T16:37:08.350420648Z",
                    "recipients": [
                        "victim-test9@demistodev.onmicrosoft.com"
                    ],
                    "recipientsdomain": [
                        "onmicrosoft.com"
                    ],
                    "severity": 0,
                    "similarity": 0.9704949588309458,
                    "status": 1
                },
                {
                    "emailfrom": "paypalsupport@paypaI.com",
                    "emailfromdomain": "paypaI.com",
                    "id": "844",
                    "name": "Verify your PayPal account 838",
                    "occurred": "2021-11-28T16:37:08.471669189Z",
                    "recipients": [
                        "victim-test10@demistodev.onmicrosoft.com"
                    ],
                    "recipientsdomain": [
                        "onmicrosoft.com"
                    ],
                    "severity": 0,
                    "similarity": 0.9704949588309458,
                    "status": 1
                }
            ],
            "indicators": [
                {
                    "id": "1263",
                    "value": "http://www.lizsol.com"
                },
                {
                    "id": "1276",
                    "value": "www.lizsol.com"
                },
                {
                    "id": "1328",
                    "value": "paypalsupport@paypaI.com"
                },
                {
                    "id": "1240",
                    "value": "http://www.paypal.com/account/verify"
                },
                {
                    "id": "1243",
                    "value": "paypai.com"
                },
                {
                    "id": "1242",
                    "value": "paypal.com"
                },
                {
                    "id": "1241",
                    "value": "www.paypal.com"
                },
                {
                    "id": "1324",
                    "value": "lizsol.com"
                },
                {
                    "id": "1305",
                    "value": "demistodev.onmicrosoft.com"
                },
                {
                    "id": "1346",
                    "value": "victim-test9@demistodev.onmicrosoft.com"
                }
            ],
            "involvedIncidentsCount": 8,
            "isCampaignFound": True
        },
        "ExistingCampaignID": [
            None
        ],
        "brandInstances": [
            "Demisto Lock_instance_1"
        ]
    }


INCIDENTS_BY_ID = {'0': CAMPAIGN_INCIDENT_CONTEXT, '1': NEW_EMPTY_CAMPAIGN, '3': OLD_INCIDENT_CONTEXT,
                   '4': NEW_INCIDENT_2_CONTEXT, '5': NEW_INCIDENT_CONTEXT, '6': REAL_INCIDENT}
