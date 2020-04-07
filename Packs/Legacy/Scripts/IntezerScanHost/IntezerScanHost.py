import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import uuid

demisto.executeCommand('createNewIndicator', {'value': demisto.args()['host'], 'type': 'hostname'})
endpoint_analysis_id = str(uuid.uuid4())
scanner_result = demisto.executeCommand('IntezerRunScanner',
                                        {
                                            'endpoint_analysis_id': endpoint_analysis_id,
                                            'api_key': demisto.args()['intezer_api_key'],
                                            'using': demisto.args()['host']
                                        })
if isError(scanner_result[0]):
    demisto.results(scanner_result)

context_json = {'Intezer.Analysis': {'ID': endpoint_analysis_id,
                                     'Type': 'Endpoint',
                                     'Status': 'Created'}}

return_outputs('Endpoint analysis created', context_json)
