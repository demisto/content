from CommonServerPython import *

indicator_value = demisto.args().get('indicator_value')

sha1Regex = r'\b[a-fA-F\d]{40}\b'
indicator_type = 'serialNumber'
if re.match(emailRegex, indicator_value):
    indicator_type = 'subjectEmailAddress'
if re.match(sha1Regex, indicator_value):
    indicator_type = 'sha1'

result = demisto.executeCommand('pt-ssl-cert-search', {'field': indicator_type, 'query': indicator_value})

demisto.results(result)
