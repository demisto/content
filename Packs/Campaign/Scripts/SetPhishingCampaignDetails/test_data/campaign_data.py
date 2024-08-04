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
NEW_INCIDENT_REMOVE_CONTEXT = {
    "incident": {
        "CustomFields": {"removedfromcampaigns": ['0']},
    },
    "EmailCampaign": {
        "firstIncidentDate": "2021-11-21T14:00:07.425185+00:00",
        "incidents": [
            {
                "emailfrom": "examplesupport@example2.com",
                "emailfromdomain": "example.com",
                "id": "6",
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
NEW_EMPTY_CAMPAIGN = {}


INCIDENTS_BY_ID = {'0': CAMPAIGN_INCIDENT_CONTEXT, '1': NEW_EMPTY_CAMPAIGN, '3': OLD_INCIDENT_CONTEXT,
                   '4': NEW_INCIDENT_2_CONTEXT, '5': NEW_INCIDENT_CONTEXT, '6': NEW_INCIDENT_REMOVE_CONTEXT}
