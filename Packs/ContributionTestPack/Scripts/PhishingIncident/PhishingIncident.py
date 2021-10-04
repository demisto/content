import base64

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

MALICIOUS_TEXT = '2d8bb37078ff9efd02d9361975c9e625ae56bd8a8a65d50fc568341bc88392ae'

args = demisto.args()

incidents = {
    'name': args['malicious_location'],
    'labels': json.dumps([
        {'Email/from': 'test@demistodev.com'},
        {'Email/to': 'admin@demistodev.com'},
    ]),
    'rawJSON': json.dumps({
        'Type': 'Phish',
        'Subject': 'Phishing test playbook',
        'To': 'admin@demistodev.com',
        'From': 'test@demistodev.com',
    })
}

demisto.executeCommand("setIncident", incidents)
