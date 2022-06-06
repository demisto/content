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
