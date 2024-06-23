WITH_OUT_DUP_TEST = {
    'audit_events': [
        {
            "id": "eNoVzkkOgjAAQNG7dAuLtkzFxEUVJaYJQxAJS4WKJUIJUECNdxcP8PL_Bwy8UD0XJdiA1xKq3IdnldjJMxbKzyChovHbilke6ZZ9dXo8nGPENOuQ1_dTmt1vamJuGNAgwri-pGgYy4LjCe7aWctdj81nz7EafJBjQwyze8eLEU0wolugg6sqxfiU1b-NHJMgjExLB4UaRtnwvpAlX6f2aUIRxBQb9mom3g9Ctiv4_gBtPjta",
            "auditType": "User Logged On",
            "user": "outbound-auth@journal.paloaltonetworks.mime.integration.com",
            "eventTime": "2022-05-28T12:55:22+0000",
            "eventInfo": "Successful authentication for outbound-auth@journal.paloaltonetworks.mime.integration.com <SMTP Outbound Auth>, Date: 2022-05-28, Time: 08:55:22 GMT-04:00, IP: 1.2.3.4, Application: SMTP-MTA2, Method: Cloud",
            "category": "authentication_logs"
        },
        {
            "id": "eNoVztsKgjAAgOF32a1Bbp6DLpZaiaGLtAN0U3MeIp2oUyt69-wBPv7_A1pGRcOKBCyACMfzyS6kJ91GRNld55mHI-1VbqrM1xyzHu3My3NjTXxJcy-P1ItP6V30vhUGOCAIPY4xbLuEMtTLq2qQLpbjD5FjaCVyeVeailq_96NCepngJZiBm0iK7smzfxwaqgmhpeszQEXb8ZI1lCdsurLjA4YywkjRJ9Ozpi14NYHvD3mfO2k",
            "auditType": "User Logged On",
            "user": "outbound-auth@journal.paloaltonetworks.mime.integration.com",
            "eventTime": "2022-05-28T08:00:21+0000",
            "eventInfo": "Successful authentication for outbound-auth@journal.paloaltonetworks.mime.integration.com <SMTP Outbound Auth>, Date: 2022-05-28, Time: 04:00:21 GMT-04:00, IP: 1.2.3.4, Application: SMTP-MTA2, Method: Cloud",
            "category": "authentication_logs"
        }],

    'last_run_potential_dup': [
        '12345',
        'SDGSFDGS4345434534'
    ]
}

WITH_DUP_TEST = {
    'audit_events': [
        {
            "id": "eNoVzkkOgjAAQNG7dAuLtkzFxEUVJaYJQxAJS4WKJUIJUECNdxcP8PL_Bwy8UD0XJdiA1xKq3IdnldjJMxbKzyChovHbilke6ZZ9dXo8nGPENOuQ1_dTmt1vamJuGNAgwri-pGgYy4LjCe7aWctdj81nz7EafJBjQwyze8eLEU0wolugg6sqxfiU1b-NHJMgjExLB4UaRtnwvpAlX6f2aUIRxBQb9mom3g9Ctiv4_gBtPjta",
            "auditType": "User Logged On",
            "user": "outbound-auth@journal.paloaltonetworks.mime.integration.com",
            "eventTime": "2022-05-28T12:55:22+0000",
            "eventInfo": "Successful authentication for outbound-auth@journal.paloaltonetworks.mime.integration.com <SMTP Outbound Auth>, Date: 2022-05-28, Time: 08:55:22 GMT-04:00, IP: 1.2.3.4, Application: SMTP-MTA2, Method: Cloud",
            "category": "authentication_logs"
        },
        {
            "id": "eNoVztsKgjAAgOF32a1Bbp6DLpZaiaGLtAN0U3MeIp2oUyt69-wBPv7_A1pGRcOKBCyACMfzyS6kJ91GRNld55mHI-1VbqrM1xyzHu3My3NjTXxJcy-P1ItP6V30vhUGOCAIPY4xbLuEMtTLq2qQLpbjD5FjaCVyeVeailq_96NCepngJZiBm0iK7smzfxwaqgmhpeszQEXb8ZI1lCdsurLjA4YywkjRJ9Ozpi14NYHvD3mfO2k",
            "auditType": "User Logged On",
            "user": "outbound-auth@journal.paloaltonetworks.mime.integration.com",
            "eventTime": "2022-05-28T08:00:21+0000",
            "eventInfo": "Successful authentication for outbound-auth@journal.paloaltonetworks.mime.integration.com <SMTP Outbound Auth>, Date: 2022-05-28, Time: 04:00:21 GMT-04:00, IP: 1.2.3.4, Application: SMTP-MTA2, Method: Cloud",
            "category": "authentication_logs"
        },
        {
            "id": "123",
            "auditType": "User Logged On",
            "user": "outbound-auth@journal.paloaltonetworks.mime.integration.com",
            "eventTime": "2022-05-28T08:00:21+0000",
            "eventInfo": "Successful authentication for outbound-auth@journal.paloaltonetworks.mime.integration.com <SMTP Outbound Auth>, Date: 2022-05-28, Time: 04:00:21 GMT-04:00, IP: 1.2.3.4, Application: SMTP-MTA2, Method: Cloud",
            "category": "authentication_logs"
        }
    ],

    'last_run_potential_dup': [
        '123',
        'eNoVztsKgjAAgOF32a1Bbp6DLpZaiaGLtAN0U3MeIp2oUyt69-wBPv7_A1pGRcOKBCyACMfzyS6kJ91GRNld55mHI-1VbqrM1xyzHu3My3NjTXxJcy-P1ItP6V30vhUGOCAIPY4xbLuEMtTLq2qQLpbjD5FjaCVyeVeailq_96NCepngJZiBm0iK7smzfxwaqgmhpeszQEXb8ZI1lCdsurLjA4YywkjRJ9Ozpi14NYHvD3mfO2k'
    ],
    'res': [{
        "id": "eNoVzkkOgjAAQNG7dAuLtkzFxEUVJaYJQxAJS4WKJUIJUECNdxcP8PL_Bwy8UD0XJdiA1xKq3IdnldjJMxbKzyChovHbilke6ZZ9dXo8nGPENOuQ1_dTmt1vamJuGNAgwri-pGgYy4LjCe7aWctdj81nz7EafJBjQwyze8eLEU0wolugg6sqxfiU1b-NHJMgjExLB4UaRtnwvpAlX6f2aUIRxBQb9mom3g9Ctiv4_gBtPjta",
        "auditType": "User Logged On",
        "user": "outbound-auth@journal.paloaltonetworks.mime.integration.com",
        "eventTime": "2022-05-28T12:55:22+0000",
        "eventInfo": "Successful authentication for outbound-auth@journal.paloaltonetworks.mime.integration.com <SMTP Outbound Auth>, Date: 2022-05-28, Time: 08:55:22 GMT-04:00, IP: 1.2.3.4, Application: SMTP-MTA2, Method: Cloud",
        "category": "authentication_logs"
    }]
}

EMPTY_EVENTS_LIST = {
    'audit_events': [],
    'last_run_potential_dup': ['123', 'LKJFDIGO87S443', 'SADF'],
    'res': []
}

FILTER_SAME_TIME_EVEMTS = {
    'audit_response': {
        "meta": {
            "status": 200,
            "pagination": {
                "pageSize": 230,
                "next": "eNotj8sKgkAUQP_lbhUyUyqhhWVFSDbRG9r4uNqYOjbjTFL070W1PHAW5zyhDjMU9IE0Acc2DB0ExpJ_Eaz8lhZtq8WIm2WktHPHwnPnuCnnVebb3qBuJ9nicunPiK_Z01OeLnaHNJLKH64CNyCmme93XdEkMZrKGFd37TT0_PvW69ulOWVNOehZ9WPd9ogyiDsC_RsTyDJCDs4nhQrCUVEmBThpWAj8GVt2xQqcShaFDgq5oOyDXR04xownogl58995vQHKLUrC"
            }
        },
        "data": [
            {
                "id": "eNoVzt0KgjAAQOF32a1B23SpQRemZrEoKy2EbkrnT6ULndOK3j17gI9zPqBhcVuzIgFToPEAEk_a6xotozs5j_eQMvEqvSqjxDGevZ2t8lxf-FQhbnRLV-EpvbaSmtuNtfExvh1D1IgkZljCedUpkenQLnB0UmKXi9JQted716u-hL41AyNwaZNCPHj2jyNdM5BhIm0E4rYRvGR1zBM2XNnhwUIQW1idDEayuil4NYDvD0ccOyU",
                "auditType": "User Logged On",
                "user": "outbound-auth@journal.paloaltonetworks.mime.integration.com",
                "eventTime": "2022-05-31T12:50:33+0000",
                "eventInfo": "Successful authentication for outbound-auth@journal.paloaltonetworks.mime.integration.com <SMTP Outbound Auth>, Date: 2022-05-31, Time: 08:50:33 GMT-04:00, IP: 1.2.3.4, Application: SMTP-MTA2, Method: Cloud",
                "category": "authentication_logs"
            },
            {
                "id": "eNoVzkkOgjAAQNG7dIsLWkCKiQsmCWKwKkhYIpQpQAmUIRrvLh7g5f8PGGk6DbTKwAH0pE4aJViwYfEIXfD93CyO2Tpd4SkW7lezcMtSPRFPUOy4zt0wyl_T7GlXX_cJQvUzhCPPUopm0egWIdYsbwksVWmRzXiLJbl_31aJzCLRj2AHkimreMOKfxuqMoZYg9IOpNPIWUuHlGV0mzLDhw5FpCNpv5mZDmPFug18f0rLOy0",
                "auditType": "User Logged On",
                "user": "outbound-auth@journal.paloaltonetworks.mime.integration.com",
                "eventTime": "2022-05-31T12:50:33+0000",
                "eventInfo": "Successful authentication for outbound-auth@journal.paloaltonetworks.mime.integration.com <SMTP Outbound Auth>, Date: 2022-05-31, Time: 08:50:33 GMT-04:00, IP: 1.2.3.4, Application: SMTP-MTA2, Method: Cloud",
                "category": "authentication_logs"
            },
            {
                "id": "eNoVzkkOgjAAQNG7dCsLWmYTFwUca7AEkbDEtiDGUsNoNN5dPMDL_x_QCTa0ouZgCQ6Gj6-ZWcRyYjtYUH7EEUnktqmIFbrPV1DtbzdnQ8nCWuf3cp9m5XUYiXeKcEQRul9S2PWcCTTqfjMtci8k0zl0LInWqpeuYT7f8cugo07xCmigGHjdP1T1b0PHdKFnQ0cDbOh6JUXLFBfzVJAmGOoII8OezSjarlbNDL4_Ets63Q",
                "auditType": "User Logged On",
                "user": "outbound-auth@journal.paloaltonetworks.mime.integration.com",
                "eventTime": "2022-05-31T11:35:31+0000",
                "eventInfo": "Successful authentication for outbound-auth@journal.paloaltonetworks.mime.integration.com <SMTP Outbound Auth>, Date: 2022-05-31, Time: 09:35:31 GMT-04:00, IP: 1.2.3.4, Application: SMTP-MTA2, Method: Cloud",
                "category": "authentication_logs"
            },
            {
                "id": "eNoVzkkOgjAAQNG7dIsLWmYTF5WiQSJiFAlLKWVSKAIFovHu4gFe_v-AnlHRsTIFa5AcuYviB3Qw0cmBvqJJ8Mau903uacRsZzt3i8LYBZ6kOXGVuWGUJWL0rJOP_QCh6hbCfkgpQ6O8bSYptog3XYmh1cjhQ20qavs-z0owygHegBW4i7Qcnjz_t6GhmtCCqrECVPQDr1lHecqWKTu8YCgjjBR9MSPr-pI3C_j-AFEpO0E",
                "auditType": "User Logged On",
                "user": "outbound-auth@journal.paloaltonetworks.mime.integration.com",
                "eventTime": "2022-05-31T9:05:31+0000",
                "eventInfo": "Successful authentication for outbound-auth@journal.paloaltonetworks.mime.integration.com <SMTP Outbound Auth>, Date: 2022-05-31, Time: 09:05:31 GMT-04:00, IP: 1.2.3.4, Application: SMTP-MTA2, Method: Cloud",
                "category": "authentication_logs"
            },
        ]
    },
    'res': [
        {
            "id": "eNoVzt0KgjAAQOF32a1B23SpQRemZrEoKy2EbkrnT6ULndOK3j17gI9zPqBhcVuzIgFToPEAEk_a6xotozs5j_eQMvEqvSqjxDGevZ2t8lxf-FQhbnRLV-EpvbaSmtuNtfExvh1D1IgkZljCedUpkenQLnB0UmKXi9JQted716u-hL41AyNwaZNCPHj2jyNdM5BhIm0E4rYRvGR1zBM2XNnhwUIQW1idDEayuil4NYDvD0ccOyU",
            "auditType": "User Logged On",
            "user": "outbound-auth@journal.paloaltonetworks.mime.integration.com",
            "eventTime": "2022-05-31T12:50:33+0000",
            "eventInfo": "Successful authentication for outbound-auth@journal.paloaltonetworks.mime.integration.com <SMTP Outbound Auth>, Date: 2022-05-31, Time: 08:50:33 GMT-04:00, IP: 1.2.3.4, Application: SMTP-MTA2, Method: Cloud",
            "category": "authentication_logs"
        },
        {
            "id": "eNoVzkkOgjAAQNG7dIsLWkCKiQsmCWKwKkhYIpQpQAmUIRrvLh7g5f8PGGk6DbTKwAH0pE4aJViwYfEIXfD93CyO2Tpd4SkW7lezcMtSPRFPUOy4zt0wyl_T7GlXX_cJQvUzhCPPUopm0egWIdYsbwksVWmRzXiLJbl_31aJzCLRj2AHkimreMOKfxuqMoZYg9IOpNPIWUuHlGV0mzLDhw5FpCNpv5mZDmPFug18f0rLOy0",
            "auditType": "User Logged On",
            "user": "outbound-auth@journal.paloaltonetworks.mime.integration.com",
            "eventTime": "2022-05-31T12:50:33+0000",
            "eventInfo": "Successful authentication for outbound-auth@journal.paloaltonetworks.mime.integration.com <SMTP Outbound Auth>, Date: 2022-05-31, Time: 08:50:33 GMT-04:00, IP: 1.2.3.4, Application: SMTP-MTA2, Method: Cloud",
            "category": "authentication_logs"
        }
    ]
}

AUDIT_LOG_RESPONSE = {
    "meta": {
        "status": 200,
        "pagination": {
            "pageSize": 10,
            "next": "1234"
        }
    },
    "data": [
        {
            "id": "eNoVzkkOgjAAQNG7dAsLKEOLiQsmDSGBqqCyFChThBLKFIx3Fw_w8v8HcJpNA61zcAAW7rF-5bGUPoOKNE6Itmix23NX-pqD-9UuvapCJ-ILmps0hRc_inSafSMMzIBA2NxjmY95RuEsWd0iJIbjL5GDtBa6bGyxovbbZVXILBHzCETwmvJ6fLPy35aRimVFxUgE2cRH1tIhYzndp-z4ZsoSNKGi72amA69Zt4PvDzAYOw0",
            "auditType": "User Logged On",
            "user": "outbound-auth@journal.paloaltonetworks.mime.integration.com",
            "eventTime": "2022-05-29T10:43:25+0000",
            "eventInfo": "Successful authentication for outbound-auth@journal.paloaltonetworks.mime.integration.com <SMTP Outbound Auth>, Date: 2022-05-29, Time: 06:43:25 GMT-04:00, IP: 1.2.3.4, Application: SMTP-MTA2, Method: Cloud",
            "category": "authentication_logs"
        },
        {
            "id": "eNoVzkkOgjAAQNG7dIsLKCBg4oJJgiRQo4AstZQplhKghWi8u3iAl_8_YCKYj6QtwQHEPM9ogh0hMofeZZai4Oy0NOjrSPfMYXXrsGmME4ok3S-6Kkzz6slFZCWxHSMIuyxVprnEBArZ6RepsLxouXmGTqHPZmqq2vC-rCoSMrKPYAcevGznF6v_bcXQTEXVoLUDmE8zo2TErCTblJtebUWGNlT3mxFknFrWb-D7A4RpO4U",
            "auditType": "User Logged On",
            "user": "outbound-auth@journal.paloaltonetworks.mime.integration.com",
            "eventTime": "2022-05-29T08:43:25+0000",
            "eventInfo": "Successful authentication for outbound-auth@journal.paloaltonetworks.mime.integration.com <SMTP Outbound Auth>, Date: 2022-05-29, Time: 04:43:25 GMT-04:00, IP: 1.2.3.4, Application: SMTP-MTA2, Method: Cloud",
            "category": "authentication_logs"
        },
        {
            "id": "eNoVzt0KgjAAQOF32a2COrVZ0IVphQ3UfiwKb0yXTZoT58yK3j17gI9zPkCQXLaEFmAG9s3aoaddqqUa2ujyElXiZWWCsnVdYtt3msErg_sdrWKs2MtzdQuS0-0qezyNQjeMIayOiSG6Iiew1xf1UzlPffw8-MhmcMk75phW894OZtzrsTsHKshkQbsHL_91A1mOYUKEVJBL0XFG2pwXZNzykr1r6NCF5mQ0PWkF5fUIvj_Pojvs",
            "auditType": "User Logged On",
            "user": "outbound-auth@journal.paloaltonetworks.mime.integration.com",
            "eventTime": "2022-05-29T05:03:24+0000",
            "eventInfo": "Successful authentication for outbound-auth@journal.paloaltonetworks.mime.integration.com <SMTP Outbound Auth>, Date: 2022-05-29, Time: 01:03:24 GMT-04:00, IP: 1.2.3.4, Application: SMTP-MTA2, Method: Cloud",
            "category": "authentication_logs"
        }
    ],
    "fail": []
}

AUDIT_LOG_AFTER_PROCESS = [
    {
        "id": "eNoVzkkOgjAAQNG7dAsLKEOLiQsmDSGBqqCyFChThBLKFIx3Fw_w8v8HcJpNA61zcAAW7rF-5bGUPoOKNE6Itmix23NX-pqD-9UuvapCJ-ILmps0hRc_inSafSMMzIBA2NxjmY95RuEsWd0iJIbjL5GDtBa6bGyxovbbZVXILBHzCETwmvJ6fLPy35aRimVFxUgE2cRH1tIhYzndp-z4ZsoSNKGi72amA69Zt4PvDzAYOw0",
        "auditType": "User Logged On",
        "user": "outbound-auth@journal.paloaltonetworks.mime.integration.com",
        "eventTime": "2022-05-29T10:43:25+0000",
        "eventInfo": "Successful authentication for outbound-auth@journal.paloaltonetworks.mime.integration.com <SMTP Outbound Auth>, Date: 2022-05-29, Time: 06:43:25 GMT-04:00, IP: 1.2.3.4, Application: SMTP-MTA2, Method: Cloud",
        "category": "authentication_logs",
        "xsiem_classifier": "audit_event"
    },
    {
        "id": "eNoVzkkOgjAAQNG7dIsLKCBg4oJJgiRQo4AstZQplhKghWi8u3iAl_8_YCKYj6QtwQHEPM9ogh0hMofeZZai4Oy0NOjrSPfMYXXrsGmME4ok3S-6Kkzz6slFZCWxHSMIuyxVprnEBArZ6RepsLxouXmGTqHPZmqq2vC-rCoSMrKPYAcevGznF6v_bcXQTEXVoLUDmE8zo2TErCTblJtebUWGNlT3mxFknFrWb-D7A4RpO4U",
        "auditType": "User Logged On",
        "user": "outbound-auth@journal.paloaltonetworks.mime.integration.com",
        "eventTime": "2022-05-29T08:43:25+0000",
        "eventInfo": "Successful authentication for outbound-auth@journal.paloaltonetworks.mime.integration.com <SMTP Outbound Auth>, Date: 2022-05-29, Time: 04:43:25 GMT-04:00, IP: 1.2.3.4, Application: SMTP-MTA2, Method: Cloud",
        "category": "authentication_logs",
        "xsiem_classifier": "audit_event"
    },
    {
        "id": "eNoVzt0KgjAAQOF32a2COrVZ0IVphQ3UfiwKb0yXTZoT58yK3j17gI9zPkCQXLaEFmAG9s3aoaddqqUa2ujyElXiZWWCsnVdYtt3msErg_sdrWKs2MtzdQuS0-0qezyNQjeMIayOiSG6Iiew1xf1UzlPffw8-MhmcMk75phW894OZtzrsTsHKshkQbsHL_91A1mOYUKEVJBL0XFG2pwXZNzykr1r6NCF5mQ0PWkF5fUIvj_Pojvs",
        "auditType": "User Logged On",
        "user": "outbound-auth@journal.paloaltonetworks.mime.integration.com",
        "eventTime": "2022-05-29T05:03:24+0000",
        "eventInfo": "Successful authentication for outbound-auth@journal.paloaltonetworks.mime.integration.com <SMTP Outbound Auth>, Date: 2022-05-29, Time: 01:03:24 GMT-04:00, IP: 1.2.3.4, Application: SMTP-MTA2, Method: Cloud",
        "category": "authentication_logs",
        "xsiem_classifier": "audit_event"
    }
]

SIEM_LOG_PROCESS_EVENT = [
    {
        'siem_data_response': {
            "type": "MTA",
            "data": [
                {
                    "acc": "CUSA102A236",
                    "Delivered": False,
                    "Err": "Connection refused (Connection refused)",
                    "RejType": "Recipient server unavailable or busy",
                    "AttCnt": 0,
                    "Dir": "Inbound",
                    "ReceiptAck": None,
                    "MsgId": "<fakeId>",
                    "Subject": "Tesing Out of Office Agent",
                    "Latency": 43470985,
                    "Sender": "enronmessaging@pacific-concept.b41.one",
                    "datetime": "2022-06-08T13:02:06-0400",
                    "Rcpt": [
                        "jeff.skilling@paloaltonetworks.mime.integration.com"
                    ],
                    "AttSize": 0,
                    "Attempt": 17,
                    "Snt": 0,
                    "aCode": "xBACPCanOqaYecLvf58JhA",
                    "UseTls": "No",
                    "type": "MTA",
                    "xsiem_classifier": "siem_log"
                }
            ]
        },
        'after_process': [{
            "acc": "CUSA102A236",
            "Delivered": False,
            "Err": "Connection refused (Connection refused)",
            "RejType": "Recipient server unavailable or busy",
            "AttCnt": 0,
            "Dir": "Inbound",
            "ReceiptAck": None,
            "MsgId": "<fakeId>",
            "Subject": "Tesing Out of Office Agent",
            "Latency": 43470985,
            "Sender": "enronmessaging@pacific-concept.b41.one",
            "datetime": "2022-06-08T13:02:06-0400",
            "Rcpt": [
                "jeff.skilling@paloaltonetworks.mime.integration.com"
            ],
            "AttSize": 0,
            "Attempt": 17,
            "Snt": 0,
            "aCode": "xBACPCanOqaYecLvf58JhA",
            "UseTls": "No",
            "type": "MTA",
            "xsiem_classifier": "siem_log"
        }]
    }
]

SIEM_RESPONSE_MULTIPLE_EVENTS = {
    "type": "MTA",
    "data": [
        {
            "acc": "CUSA102A236",
            "SpamLimit": 28,
            "IP": "1.2.3.4",
            "Dir": "Outbound",
            "Subject": "Re",
            "MsgId": "<fakeId>",
            "headerFrom": "mark.guzman@paloaltonetworks.mime.integration.com",
            "Sender": "mark.guzman@paloaltonetworks.mime.integration.com",
            "datetime": "2022-05-23T12:20:44-0400",
            "Rcpt": "chartman@pilot-meadow.b41.one",
            "SpamInfo": "[]",
            "Act": "Acc",
            "TlsVer": "TLSv1.2",
            "Cphr": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "aCode": "l1b4x0uvOs2sRFzGsHoYzQ",
            "SpamScore": 0
        },
        {
            "acc": "CUSA102A236",
            "SpamLimit": 28,
            "IP": "1.2.3.4",
            "Dir": "Outbound",
            "Subject": "Re",
            "MsgId": "<fakeId>",
            "headerFrom": "jeff.dasovich@paloaltonetworks.mime.integration.com",
            "Sender": "jeff.dasovich@paloaltonetworks.mime.integration.com",
            "datetime": "2022-05-23T12:20:48-0400",
            "Rcpt": "jito@demo-visionary.b41.one",
            "SpamInfo": "[]",
            "Act": "Acc",
            "TlsVer": "TLSv1.2",
            "Cphr": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "aCode": "-dogI8BBMquuevdHEC83Lw",
            "SpamScore": 0
        },
        {
            "acc": "CUSA102A236",
            "SpamLimit": 28,
            "IP": "1.2.3.4",
            "Dir": "Outbound",
            "Subject": "Re",
            "MsgId": "<fakeId>",
            "headerFrom": "jeff.dasovich@paloaltonetworks.mime.integration.com",
            "Sender": "jeff.dasovich@paloaltonetworks.mime.integration.com",
            "datetime": "2022-05-23T12:20:48-0400",
            "Rcpt": "dimeff@demo-visionary.b41.one",
            "SpamInfo": "[]",
            "Act": "Acc",
            "TlsVer": "TLSv1.2",
            "Cphr": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "aCode": "-dogI8BBMquuevdHEC83Lw",
            "SpamScore": 0
        }
    ]
}

SIEM_RESULT_MULTIPLE_EVENTS_PROCESS = [
    {
        "acc": "CUSA102A236",
        "SpamLimit": 28,
        "IP": [
            "1.2.3.4"
        ],
        "Dir": "Outbound",
        "Subject": "Re",
        "MsgId": "<fakeId>",
        "headerFrom": "mark.guzman@paloaltonetworks.mime.integration.com",
        "Sender": "mark.guzman@paloaltonetworks.mime.integration.com",
        "datetime": "2022-05-23T12:20:44-0400",
        "Rcpt": ["chartman@pilot-meadow.b41.one"],
        "SpamInfo": "[]",
        "Act": "Acc",
        "TlsVer": "TLSv1.2",
        "Cphr": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "aCode": "l1b4x0uvOs2sRFzGsHoYzQ",
        "SpamScore": 0,
        "type": "MTA",
        "xsiem_classifier": "siem_log"
    },
    {
        "acc": "CUSA102A236",
        "SpamLimit": 28,
        "IP": [
            "1.2.3.4"
        ],
        "Dir": "Outbound",
        "Subject": "Re",
        "MsgId": "<fakeId>",
        "headerFrom": "jeff.dasovich@paloaltonetworks.mime.integration.com",
        "Sender": "jeff.dasovich@paloaltonetworks.mime.integration.com",
        "datetime": "2022-05-23T12:20:48-0400",
        "Rcpt": ["jito@demo-visionary.b41.one"],
        "SpamInfo": "[]",
        "Act": "Acc",
        "TlsVer": "TLSv1.2",
        "Cphr": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "aCode": "-dogI8BBMquuevdHEC83Lw",
        "SpamScore": 0,
        "type": "MTA",
        "xsiem_classifier": "siem_log"
    },
    {
        "acc": "CUSA102A236",
        "SpamLimit": 28,
        "IP": [
            "1.2.3.4"
        ],
        "Dir": "Outbound",
        "Subject": "Re",
        "MsgId": "<fakeId>",
        "headerFrom": "jeff.dasovich@paloaltonetworks.mime.integration.com",
        "Sender": "jeff.dasovich@paloaltonetworks.mime.integration.com",
        "datetime": "2022-05-23T12:20:48-0400",
        "Rcpt": ["dimeff@demo-visionary.b41.one"],
        "SpamInfo": "[]",
        "Act": "Acc",
        "TlsVer": "TLSv1.2",
        "Cphr": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "aCode": "-dogI8BBMquuevdHEC83Lw",
        "SpamScore": 0,
        "type": "MTA",
        "xsiem_classifier": "siem_log"
    }
]
