import demistomock as demisto
from CommonServerPython import *

res = demisto.searchIndicators(query='type:"MITRE ATT&CK" and investigationsCount:>0')


indicators = []
for ind in res['iocs']:
    indicators.append({
        'Value': dict_safe_get(ind, ['value']),
        'Name': dict_safe_get(ind, ['CustomFields', 'mitrename']),
        'Phase Name': dict_safe_get(ind, ['CustomFields', 'mitrekillchainphases', 0, 'phase_name']),
        'Description': dict_safe_get(ind, ['CustomFields', 'mitredescription']),

    })

temp = tableToMarkdown('MITRE ATT&CK techniques by open Incidents', indicators,
                       headers=['Value', 'Name', 'Phase Name', 'Description'])
return_outputs(temp)
