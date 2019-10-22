from CommonServerPython import *


the_input = demisto.args().get('input')
args = {
    'input': the_input,
    'extractFQDN': 'true'
}

demisto.results(demisto.executeCommand('ExtractDomainFromUrlAndEmail', args))
