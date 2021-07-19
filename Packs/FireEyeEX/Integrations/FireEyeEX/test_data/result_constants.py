GET_ALERTS_CONTEXT = [
    {'ack': 'no',
     'action': 'notified',
     'alertUrl': 'https://FireEyeEX/emps/eanalysis?e_id=9&type=url',
     'applianceId': 'appid',
     'attackTime': '2021-02-14 09:42:43 +0000',
     'dst': {'smtpTo': 'test@actualdomain.org'},
     'explanation': {'malwareDetected': {'malware': [{'md5Sum': '271c1bcd28d01c6863fdb5b5c5d94e73',
                                                      'name': 'FETestEvent',
                                                      'sha256': 'abebb5862eea61a3d0a1c75bf5a2e2abcd6c4ee6a6ad086e1d518445594970fc'}]},
                     'osChanges': []},
     'id': 1,
     'malicious': 'yes',
     'name': 'MALWARE_OBJECT',
     'occurred': '2021-02-14 09:42:47 +0000',
     'product': 'EMAIL_MPS',
     'scVersion': '1115.212',
     'severity': 'MAJR',
     'smtpMessage': {'subject': 'test'},
     'src': {'smtpMailFrom': 'test@malicious.net'},
     'uuid': 'uuid',
     'vlan': 0},
    {'ack': 'no',
     'action': 'notified',
     'alertUrl': 'https://FireEyeEX/emps/eanalysis?e_id=10&type=url',
     'applianceId': 'appid',
     'attackTime': '2021-02-14 09:43:51 +0000',
     'dst': {'smtpTo': 'test@actualdomain.org'},
     'explanation': {'malwareDetected': {'malware': [{'md5Sum': '6efaa05d0d98711416f7d902639155fb',
                                                      'name': 'FETestEvent',
                                                      'sha256': '340d367ebe68ad833ea055cea7678463a896d03eae86f7816cc0c836b9508fa8'}]},
                     'osChanges': []},
     'id': 2,
     'malicious': 'yes',
     'name': 'MALWARE_OBJECT',
     'occurred': '2021-02-14 09:43:55 +0000',
     'product': 'EMAIL_MPS',
     'scVersion': '1115.212',
     'severity': 'MAJR',
     'smtpMessage': {'subject': 'test'},
     'src': {'smtpMailFrom': 'test@malicious.net'},
     'uuid': 'uuid',
     'vlan': 0}]
GET_ALERTS_DETAILS_CONTEXT = [
    {'ack': 'no',
     'action': 'notified',
     'alertUrl': 'https://FireEyeEX/emps/eanalysis?e_id=12&type=url',
     'applianceId': 'appid',
     'attackTime': '2021-02-14 09:45:55 +0000',
     'dst': {'smtpTo': 'test@actualdomain.org'},
     'explanation': {
         'malwareDetected': {'malware': [{'md5Sum': 'a705075df02f217e8bfc9ac5ec2ffee2',
                                          'name': 'Malicious.LIVE.DTI.URL',
                                          'sha256': 'd1eeadbb4e3d1c57af5a069a0886aa2b4f71484721aafe5c90708b66b8d0090a'}]},
         'osChanges': []},
     'id': 3,
     'malicious': 'yes',
     'name': 'MALWARE_OBJECT',
     'occurred': '2021-02-14 09:45:58 +0000',
     'product': 'EMAIL_MPS',
     'scVersion': '1115.212',
     'severity': 'MAJR',
     'smtpMessage': {'subject': 'test'},
     'src': {'smtpMailFrom': 'test@malicious.net'},
     'uuid': 'uuid',
     'vlan': 0}]
GET_ARTIFACTS_METADATA_CONTEXT = {
    "artifactsInfoList": [
        {
            "artifactName": "name",
            "artifactSize": "269",
            "artifactType": "original_email"
        }
    ],
    "uuid": "uuid"
}
QUARANTINED_EMAILS_CONTEXT = [
    {
        'completed_at': '2021-06-14T16:01:15',
        'email_uuid': 'email_uuid',
        'from': 'undisclosed_sender',
        'message_id': 'queue-id-queue@no-message-id',
        'quarantine_path': '/data/email-analysis/quarantine2/2021-06-14/16/queue',
        'queue_id': 'queue',
        'subject': 'test'
    },
    {
        'completed_at': '2021-06-14T16:01:15',
        'email_uuid': 'email_uuid',
        'from': 'undisclosed_sender',
        'message_id': 'queue-id-queue@no-message-id',
        'quarantine_path': '/data/email-analysis/quarantine2/2021-06-14/16/queue',
        'queue_id': 'queue',
        'subject': 'test'
    }
]
ALLOWEDLIST = [
    {
        "created_at": "2021/06/14 10:41:31",
        "matches": 7,
        "name": "www.demisto.com"
    },
    {
        "created_at": "2021/06/14 10:43:13",
        "matches": 2,
        "name": "www.demisto2.com"
    }
]
BLOCKEDLIST = [
    {
        "created_at": "2021/04/19 14:22:06",
        "matches": 0,
        "name": "gmail.com"
    },
    {
        "created_at": "2021/04/19 14:27:35",
        "matches": 0,
        "name": "www.blocksite1.net/path/test.html"
    }
]
