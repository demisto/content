import pytest

'''Globals'''
INDICATORS_EC = [
    (
        'url-phishlabs',
        {
            "url": "https://google.com/",
            "malicious": "false",
            "maliciousDomain": "false"
        },
        {
            'URL': "https://google.com/",
            'Malicious': "false",
            'MaliciousDomain': "false"
        }
    ),
    (
        'attach-phishlabs',
        {
            "fileName": "EECO_RFQ__453100Q.pdf",
            "mimeType": "application/pdf",
            "md5": "6680e7e593c8286ac51e332d8f72aeec",
            "sha256": "6b4eeb63b26d3415a529fd95e41e83af19642f2c967b3089a0de8da55c79dd47",
            "malicious": "false"
        },
        {
            'fileName': "EECO_RFQ__453100Q.pdf",
            'MimeType': "application/pdf",
            'MD5': "6680e7e593c8286ac51e332d8f72aeec",
            'SHA256': "6b4eeb63b26d3415a529fd95e41e83af19642f2c967b3089a0de8da55c79dd47",
            'Malicious': "false"
        }
    ),
    (
        'email-ec',
        {
            "caseType": "Link",
            "classification": "No Threat Detected",
            "subClassification": "No Threat Detected",
            "severity": "null",
            "emailReportedBy": "Michael Mammele <support@threatx.com>",
            "submissionMethod": "Attachment",
            "sender": "LinkedIn Sales Navigator  <support@threatx.com>",
            "emailBody": "Test body",
            "attachments": [],
            "furtherReviewReason": "null",
            "offlineUponReview": "false",
        },
        {
            'To': "Michael Mammele <support@threatx.com>",
            'From': "LinkedIn Sales Navigator  <support@threatx.com>",
            'Body/HTML': "Test body",
        }
    )
]

INDICATORS_DBOT_EC = [
    (
        'url-ec',
        {
            "url": "https://google.com/",
            "malicious": "false",
            "maliciousDomain": "false"
        },
        (
            {
                'Indicator': "https://google.com/",
                'Type': 'URL',
                'Vendor': "PhishLabs IOC - EIR",
                'Score': 1
            },
            {
                'Data': "https://google.com/",
                'Malicious': {
                    'Vendor': "PhishLabs IOC - EIR",
                    'Description': "false"
                }
            }
        )
    ),
    (
        'file-ec',
        {
            "fileName": "EECO_RFQ__453100Q.pdf",
            "mimeType": "application/pdf",
            "md5": "6680e7e593c8286ac51e332d8f72aeec",
            "sha256": "6b4eeb63b26d3415a529fd95e41e83af19642f2c967b3089a0de8da55c79dd47",
            "malicious": "false"
        },
        (
            {
                'Indicator': "EECO_RFQ__453100Q.pdf",
                'Type': 'File',
                'Vendor': "PhishLabs IOC - EIR",
                'Score': 1
            },
            {
                'Name': "EECO_RFQ__453100Q.pdf",
                'SHA256': "6b4eeb63b26d3415a529fd95e41e83af19642f2c967b3089a0de8da55c79dd47",
                'MD5': "6680e7e593c8286ac51e332d8f72aeec",
                'Malicious': {
                    'Vendor': "PhishLabs IOC - EIR",
                    'Description': "false"
                }
            }
        )
    )
]


INDICATORS_TO_LIST_EC = [
    (
        'url-ec',
        [
            {
                "url": "https://google.com/u/gI5Qk",
                "malicious": 'false',
                "maliciousDomain": 'false'
            },
            {
                "url": "https://google.com/api/track/v2/5",
                "malicious": 'false',
                "maliciousDomain": 'false'
            },
            {
                "url": "https://google.com/",
                "malicious": 'false',
                "maliciousDomain": 'false'
            }
        ],
        (
            [
                {
                    'Data': "https://google.com/u/gI5Qk",
                    'Malicious': {
                        'Vendor': "PhishLabs IOC - EIR",
                        'Description': "false"
                    }
                },
                {
                    'Data': "https://google.com/api/track/v2/5",
                    'Malicious': {
                        'Vendor': "PhishLabs IOC - EIR",
                        'Description': "false"
                    }
                },
                {
                    'Data': "https://google.com/",
                    'Malicious': {
                        'Vendor': "PhishLabs IOC - EIR",
                        'Description': "false"
                    }
                }
            ],
            [
                {
                    'Indicator': "https://google.com/u/gI5Qk",
                    'Type': 'URL',
                    'Vendor': "PhishLabs IOC - EIR",
                    'Score': 1
                },
                {
                    'Indicator': "https://google.com/api/track/v2/5",
                    'Type': 'URL',
                    'Vendor': "PhishLabs IOC - EIR",
                    'Score': 1
                },
                {
                    'Indicator': "https://google.com/",
                    'Type': 'URL',
                    'Vendor': "PhishLabs IOC - EIR",
                    'Score': 1
                }
            ]
        )
    )
]


RAW_RESPONSE_TO_CONTEXT = [
    [
        {
            "id": "INC0660360",
            "service": "EIR",
            "title": "Your operating system has been hacked by cybercriminals. Change the authorization method.",
            "description": "",
            "status": "Closed",
            "details": {
                "caseType": "Response",
                "classification": "Malicious",
                "subClassification": "Response - 419 Scam",
                "severity": "Low",
                "emailReportedBy": "PhishLabs Phishing Team <not@domain.com>",
                "submissionMethod": "Attachment",
                "sender": "<not@domain.com>",
                "emailBody": "Test",
                "urls": [
                    {
                        "url": "https://google.com/i5/resp",
                        "malicious": "false",
                        "maliciousDomain": "false"
                    }
                ],
                "attachments": [
                    {
                        "fileName": "EECO_RFQ__453100Q.pdf",
                        "mimeType": "application/pdf",
                        "md5": "6680e7e593c8286ac51e332d8f72aeec",
                        "sha256": "6b4eeb63b26d3415a529fd95e41e83af19642f2c967b3089a0de8da55c79dd47",
                        "malicious": "false"
                    }
                ],
                "furtherReviewReason": "null",
                "offlineUponReview": "false"
            },
            "created": "2019-11-01T20:55:33Z",
            "modified": "2019-11-01T21:39:57Z",
            "closed": "2019-11-01T21:39:57Z",
            "duration": 2665
        }
    ],
    (
        [
            {
                'CaseType': "Response",
                'Classification': "Malicious",
                'SubClassification': "Response - 419 Scam",
                'Severity': "Low",
                'EmailReportedBy': "PhishLabs Phishing Team <not@domain.com>",
                'SubmissionMethod': "Attachment",
                'FurtherReviewReason': "null",
                'ID': "INC0660360",
                'Title': "Your operating system has been hacked by cybercriminals. Change the authorization method.",
                'Description': "",
                'Status': "Closed",
                'Created': "2019-11-01T20:55:33Z",
                'Modified': "2019-11-01T21:39:57Z",
                'Closed': "2019-11-01T21:39:57Z",
                'Duration': 2665,
                'Email': {
                    'EmailBody': "Test",
                    'Sender': "<not@domain.com>",
                    'URL': [
                        {
                            'URL': "https://google.com/i5/resp",
                            'Malicious': "false",
                            'MaliciousDomain': "false"
                        }
                    ],
                    'Attachment': [
                        {
                            'fileName': "EECO_RFQ__453100Q.pdf",
                            'MimeType': "application/pdf",
                            'MD5': "6680e7e593c8286ac51e332d8f72aeec",
                            'SHA256': "6b4eeb63b26d3415a529fd95e41e83af19642f2c967b3089a0de8da55c79dd47",
                            'Malicious': "false"
                        }
                    ]
                }
            }
        ],
        [
            {
                'To': "PhishLabs Phishing Team <not@domain.com>",
                'From': "<not@domain.com>",
                'Body/HTML': "Test",
            }
        ],
        [
            {
                'Name': "EECO_RFQ__453100Q.pdf",
                'SHA256': "6b4eeb63b26d3415a529fd95e41e83af19642f2c967b3089a0de8da55c79dd47",
                'MD5': "6680e7e593c8286ac51e332d8f72aeec",
                'Malicious': {
                    'Vendor': "PhishLabs IOC - EIR",
                    'Description': "false"
                }
            }
        ],
        [
            {
                'Data': "https://google.com/i5/resp",
                'Malicious': {
                    'Vendor': "PhishLabs IOC - EIR",
                    'Description': "false"
                }
            }
        ],
        [
            {
                'Indicator': "EECO_RFQ__453100Q.pdf",
                'Type': 'File',
                'Vendor': "PhishLabs IOC - EIR",
                'Score': 1
            },
            {
                'Indicator': "https://google.com/i5/resp",
                'Type': "URL",
                'Vendor': "PhishLabs IOC - EIR",
                'Score': 1
            }
        ]
    )
]

'''Function tests'''


class TestHelperFunctions:
    @pytest.mark.parametrize(argnames='type_ec, test_inputs, test_outputs', argvalues=INDICATORS_EC)
    def test_indicator_ec(self, type_ec, test_inputs, test_outputs):
        from PhishLabsIOC_EIR import indicator_ec
        result = indicator_ec(indicator=test_inputs,
                              type_ec=type_ec)
        assert result == test_outputs

    @pytest.mark.parametrize(argnames='type_ec, test_inputs, test_outputs', argvalues=INDICATORS_DBOT_EC)
    def test_indicator_dbot_ec(self, type_ec, test_inputs, test_outputs):
        from PhishLabsIOC_EIR import indicator_dbot_ec
        result = indicator_dbot_ec(indicator=test_inputs,
                                   type_ec=type_ec)
        assert result == test_outputs

    @pytest.mark.parametrize(argnames='type_ec, test_inputs, test_outputs', argvalues=INDICATORS_TO_LIST_EC)
    def test_indicators_to_list_ec(self, type_ec, test_inputs, test_outputs):
        from PhishLabsIOC_EIR import indicators_to_list_ec
        result = indicators_to_list_ec(indicators=test_inputs,
                                       type_ec=type_ec)
        assert result == test_outputs

    def test_raw_response_to_context(self):
        from PhishLabsIOC_EIR import raw_response_to_context
        result = raw_response_to_context(incidents=RAW_RESPONSE_TO_CONTEXT[0])
        assert result == RAW_RESPONSE_TO_CONTEXT[1]
