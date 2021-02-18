from CommonServerPython import *

result = demisto.executeCommand('pt-get-host-pairs',
                                {'direction': 'parents', 'query': demisto.args().get('indicator_value')}
                                )

demisto.results(result)
