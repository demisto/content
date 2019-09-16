import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


FQDNs = []
the_input = demisto.args().get('input')
args = {
    'input': the_input,
    'extractFQDN': 'True'
}

demisto.results(demisto.executeCommand('ExtractDomainFromUrlAndEmail_copy', args))