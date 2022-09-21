import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

ip = demisto.args().get('indicator').get('value')
result = demisto.executeCommand('vt-passive-dns-data', {'ip': ip, 'limit': 10})[0].get('Contents').get('data')
readable_output = tableToMarkdown(
    '',
    [
        {
            'id': item['id'],
            **item['attributes']
        } for item in result
    ],
    headers=['id', 'date', 'host_name', 'ip_address', 'resolver'],
    removeNull=True,
    headerTransform=underscoreToCamelCase
)

demisto.executeCommand("setIndicator", {'value': ip, 'customFields': {'ippassivedns': readable_output}})
