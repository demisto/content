import json

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

res = True

inc = demisto.incidents()[0]
incident = {}
incident['id'] = inc['id']

demisto.debug(f'##### pre-processing incident')
incident['emailfromv4'] = inc['CustomFields']['emailfrom']
incident['emailbodyv4'] = inc['CustomFields']['emailbody']
incident['emailsubjectv4'] = inc['CustomFields']['emailsubject']
incident['emailto4'] = inc['CustomFields']['emailto']
incident['type'] = 'PhishingTestV4'
r = demisto.executeCommand('setIncident', incident)
if is_error(r):
    demisto.results(r)

demisto.results(res)
