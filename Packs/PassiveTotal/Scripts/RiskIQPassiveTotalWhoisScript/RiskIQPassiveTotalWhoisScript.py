from CommonServerPython import *

indicator_value = demisto.args().get('indicator_value')

indicator_type = 'domain'
if re.match(emailRegex, indicator_value):
    indicator_type = 'email'

result = demisto.executeCommand('pt-whois-search', {'field': indicator_type, 'query': indicator_value})

demisto.results(result)
