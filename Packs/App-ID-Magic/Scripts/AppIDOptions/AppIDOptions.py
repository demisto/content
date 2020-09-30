import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

incident = demisto.incidents()[0]
field = demisto.args()['field']

options_dict = {
    'business-systems': ['auth-service', 'database', ' erp-crm', 'general-business', 'management', 'marketing', 'office-programs', 'software-development', 'software-update', 'storage-backup'],
    'collaboration': ['email', 'instant-messaging', 'internet-conferencing', 'social-business', 'social-networking', 'voip-video', 'web-posting'],
    'general-internet': ['file-sharing', 'internet-utility'],
    'media': ['audio-streaming', 'gaming', 'photo-video'],
    'networking': ['encrypted-tunnel', 'infrastructure', 'ip-protocol', 'proxy', 'remote-access', 'routing']
}

options = options_dict[incident['CustomFields']['appidcategory']]
demisto.results({"hidden": False, "options": options})
