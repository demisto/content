WITH_OUT_DUP_TEST = {
    'audit_events': [
        {
            "id": "eNoVzkkOgjAAQNG7dAuLtkzFxEUVJaYJQxAJS4WKJUIJUECNdxcP8PL_Bwy8UD0XJdiA1xKq3IdnldjJMxbKzyChovHbilke6ZZ9dXo8nGPENOuQ1_dTmt1vamJuGNAgwri-pGgYy4LjCe7aWctdj81nz7EafJBjQwyze8eLEU0wolugg6sqxfiU1b-NHJMgjExLB4UaRtnwvpAlX6f2aUIRxBQb9mom3g9Ctiv4_gBtPjta",
            "auditType": "User Logged On",
            "user": "outbound-auth@journal.paloaltonetworks.mime.integration.com",
            "eventTime": "2022-05-28T12:55:22+0000",
            "eventInfo": "Successful authentication for outbound-auth@journal.paloaltonetworks.mime.integration.com <SMTP Outbound Auth>, Date: 2022-05-28, Time: 08:55:22 GMT-04:00, IP: 34.235.45.235, Application: SMTP-MTA2, Method: Cloud",
            "category": "authentication_logs"
        },
        {
            "id": "eNoVztsKgjAAgOF32a1Bbp6DLpZaiaGLtAN0U3MeIp2oUyt69-wBPv7_A1pGRcOKBCyACMfzyS6kJ91GRNld55mHI-1VbqrM1xyzHu3My3NjTXxJcy-P1ItP6V30vhUGOCAIPY4xbLuEMtTLq2qQLpbjD5FjaCVyeVeailq_96NCepngJZiBm0iK7smzfxwaqgmhpeszQEXb8ZI1lCdsurLjA4YywkjRJ9Ozpi14NYHvD3mfO2k",
            "auditType": "User Logged On",
            "user": "outbound-auth@journal.paloaltonetworks.mime.integration.com",
            "eventTime": "2022-05-28T08:00:21+0000",
            "eventInfo": "Successful authentication for outbound-auth@journal.paloaltonetworks.mime.integration.com <SMTP Outbound Auth>, Date: 2022-05-28, Time: 04:00:21 GMT-04:00, IP: 34.235.45.235, Application: SMTP-MTA2, Method: Cloud",
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
            "eventInfo": "Successful authentication for outbound-auth@journal.paloaltonetworks.mime.integration.com <SMTP Outbound Auth>, Date: 2022-05-28, Time: 08:55:22 GMT-04:00, IP: 34.235.45.235, Application: SMTP-MTA2, Method: Cloud",
            "category": "authentication_logs"
        },
        {
            "id": "eNoVztsKgjAAgOF32a1Bbp6DLpZaiaGLtAN0U3MeIp2oUyt69-wBPv7_A1pGRcOKBCyACMfzyS6kJ91GRNld55mHI-1VbqrM1xyzHu3My3NjTXxJcy-P1ItP6V30vhUGOCAIPY4xbLuEMtTLq2qQLpbjD5FjaCVyeVeailq_96NCepngJZiBm0iK7smzfxwaqgmhpeszQEXb8ZI1lCdsurLjA4YywkjRJ9Ozpi14NYHvD3mfO2k",
            "auditType": "User Logged On",
            "user": "outbound-auth@journal.paloaltonetworks.mime.integration.com",
            "eventTime": "2022-05-28T08:00:21+0000",
            "eventInfo": "Successful authentication for outbound-auth@journal.paloaltonetworks.mime.integration.com <SMTP Outbound Auth>, Date: 2022-05-28, Time: 04:00:21 GMT-04:00, IP: 34.235.45.235, Application: SMTP-MTA2, Method: Cloud",
            "category": "authentication_logs"
        },
        {
            "id": "123",
            "auditType": "User Logged On",
            "user": "outbound-auth@journal.paloaltonetworks.mime.integration.com",
            "eventTime": "2022-05-28T08:00:21+0000",
            "eventInfo": "Successful authentication for outbound-auth@journal.paloaltonetworks.mime.integration.com <SMTP Outbound Auth>, Date: 2022-05-28, Time: 04:00:21 GMT-04:00, IP: 34.235.45.235, Application: SMTP-MTA2, Method: Cloud",
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
        "eventInfo": "Successful authentication for outbound-auth@journal.paloaltonetworks.mime.integration.com <SMTP Outbound Auth>, Date: 2022-05-28, Time: 08:55:22 GMT-04:00, IP: 34.235.45.235, Application: SMTP-MTA2, Method: Cloud",
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
                    "eventInfo": "Successful authentication for outbound-auth@journal.paloaltonetworks.mime.integration.com <SMTP Outbound Auth>, Date: 2022-05-31, Time: 08:50:33 GMT-04:00, IP: 54.243.138.179, Application: SMTP-MTA2, Method: Cloud",
                    "category": "authentication_logs"
                },
                {
                    "id": "eNoVzkkOgjAAQNG7dIsLWkCKiQsmCWKwKkhYIpQpQAmUIRrvLh7g5f8PGGk6DbTKwAH0pE4aJViwYfEIXfD93CyO2Tpd4SkW7lezcMtSPRFPUOy4zt0wyl_T7GlXX_cJQvUzhCPPUopm0egWIdYsbwksVWmRzXiLJbl_31aJzCLRj2AHkimreMOKfxuqMoZYg9IOpNPIWUuHlGV0mzLDhw5FpCNpv5mZDmPFug18f0rLOy0",
                    "auditType": "User Logged On",
                    "user": "outbound-auth@journal.paloaltonetworks.mime.integration.com",
                    "eventTime": "2022-05-31T12:50:33+0000",
                    "eventInfo": "Successful authentication for outbound-auth@journal.paloaltonetworks.mime.integration.com <SMTP Outbound Auth>, Date: 2022-05-31, Time: 08:50:33 GMT-04:00, IP: 54.243.138.179, Application: SMTP-MTA2, Method: Cloud",
                    "category": "authentication_logs"
                },
                {
                    "id": "eNoVzkkOgjAAQNG7dCsLWmYTFwUca7AEkbDEtiDGUsNoNN5dPMDL_x_QCTa0ouZgCQ6Gj6-ZWcRyYjtYUH7EEUnktqmIFbrPV1DtbzdnQ8nCWuf3cp9m5XUYiXeKcEQRul9S2PWcCTTqfjMtci8k0zl0LInWqpeuYT7f8cugo07xCmigGHjdP1T1b0PHdKFnQ0cDbOh6JUXLFBfzVJAmGOoII8OezSjarlbNDL4_Ets63Q",
                    "auditType": "User Logged On",
                    "user": "outbound-auth@journal.paloaltonetworks.mime.integration.com",
                    "eventTime": "2022-05-31T11:35:31+0000",
                    "eventInfo": "Successful authentication for outbound-auth@journal.paloaltonetworks.mime.integration.com <SMTP Outbound Auth>, Date: 2022-05-31, Time: 09:35:31 GMT-04:00, IP: 54.243.138.179, Application: SMTP-MTA2, Method: Cloud",
                    "category": "authentication_logs"
                },
                {
                    "id": "eNoVzkkOgjAAQNG7dIsLWmYTF5WiQSJiFAlLKWVSKAIFovHu4gFe_v-AnlHRsTIFa5AcuYviB3Qw0cmBvqJJ8Mau903uacRsZzt3i8LYBZ6kOXGVuWGUJWL0rJOP_QCh6hbCfkgpQ6O8bSYptog3XYmh1cjhQ20qavs-z0owygHegBW4i7Qcnjz_t6GhmtCCqrECVPQDr1lHecqWKTu8YCgjjBR9MSPr-pI3C_j-AFEpO0E",
                    "auditType": "User Logged On",
                    "user": "outbound-auth@journal.paloaltonetworks.mime.integration.com",
                    "eventTime": "2022-05-31T9:05:31+0000",
                    "eventInfo": "Successful authentication for outbound-auth@journal.paloaltonetworks.mime.integration.com <SMTP Outbound Auth>, Date: 2022-05-31, Time: 09:05:31 GMT-04:00, IP: 54.243.138.179, Application: SMTP-MTA2, Method: Cloud",
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
                "eventInfo": "Successful authentication for outbound-auth@journal.paloaltonetworks.mime.integration.com <SMTP Outbound Auth>, Date: 2022-05-31, Time: 08:50:33 GMT-04:00, IP: 54.243.138.179, Application: SMTP-MTA2, Method: Cloud",
                "category": "authentication_logs"
            },
            {
                "id": "eNoVzkkOgjAAQNG7dIsLWkCKiQsmCWKwKkhYIpQpQAmUIRrvLh7g5f8PGGk6DbTKwAH0pE4aJViwYfEIXfD93CyO2Tpd4SkW7lezcMtSPRFPUOy4zt0wyl_T7GlXX_cJQvUzhCPPUopm0egWIdYsbwksVWmRzXiLJbl_31aJzCLRj2AHkimreMOKfxuqMoZYg9IOpNPIWUuHlGV0mzLDhw5FpCNpv5mZDmPFug18f0rLOy0",
                "auditType": "User Logged On",
                "user": "outbound-auth@journal.paloaltonetworks.mime.integration.com",
                "eventTime": "2022-05-31T12:50:33+0000",
                "eventInfo": "Successful authentication for outbound-auth@journal.paloaltonetworks.mime.integration.com <SMTP Outbound Auth>, Date: 2022-05-31, Time: 08:50:33 GMT-04:00, IP: 54.243.138.179, Application: SMTP-MTA2, Method: Cloud",
                "category": "authentication_logs"
            }
        ]
}
