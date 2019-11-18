import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import requests
import json

if demisto.command() == 'test-module':
    try:
        response = requests.get('http://emailrep.io/bill@microsoft.com')
    except:
        response = None
        pass
    if response.status_code == 200:
        demisto.results('ok')
    else:
        demisto.results('error')
    sys.exit(0)

if demisto.command() == 'email':
    getemail = 'http://emailrep.io/' + demisto.args().get('email')
    response = requests.get(getemail)
    EmailRep = {}
    content = json.loads(response.content)
    EmailRep['EmailRep'] = content
    if response.status_code == 200:
        return_outputs(tableToMarkdown(demisto.args().get('email'), content,['email','reputation','suspicious','references','details']),EmailRep,EmailRep)

    else:
        return_error("Error reaching API")

    sys.exit(0)
