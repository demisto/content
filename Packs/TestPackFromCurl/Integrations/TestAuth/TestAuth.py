import json

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# The command demisto.command() holds the command sent from the user.
if demisto.command() == 'test-module':
    # This is the call made when pressing the integration test button.
    demisto.setIntegrationContext('test-module set')
    # demisto.results('Integration context: {}'.format(demisto.getIntegrationContext()))
    demisto.results('ok')
elif demisto.command() == 'test-full-context':
    demisto.results('Full context: {}'.format(demisto.callingContext))
elif demisto.command() == 'test-set-integration-context':
    demisto.setIntegrationContext(demisto.getArg('value'))
    demisto.results('Done setting integraiton context value: {}'.format(demisto.getArg('value')))
elif demisto.command() == 'test-get-integration-context':
    # demisto.results('Integration context: {}'.format(demisto.getIntegrationContext()))
    obj = {'test': 'this'}
    demisto.setIntegrationContext(obj)
    demisto.results('Integration context: {}'.format(demisto.getIntegrationContext()['test']))
elif demisto.command() == 'test-params':
    demisto.results('Integration params: {}'.format(demisto.params()))
elif demisto.command() == 'test-integration-context-versioned':
    # res = demisto.setIntegrationContextVersioned({'val': demisto.getArg('value')}, int(demisto.getArg('version')), True)
    # demisto.results('Done setting integraiton context res: {} value: {}'.format(res, demisto.getIntegrationContextVersioned(refresh=True)))
    # test
    demisto.setIntegrationContextVersioned({'v': 'test1'}, -1, True)
    demisto.setIntegrationContextVersioned({'v': 'test2'}, -1, True)
    res = demisto.getIntegrationContextVersioned(True)
    assert res['context']['v'] == 'test2', 'something wrong with {}'.format(res)
    demisto.setIntegrationContextVersioned({'v': 'test3'}, int(res['version']), True)
    res = demisto.getIntegrationContextVersioned(True)
    assert res['context']['v'] == 'test3'
    demisto.setIntegrationContextVersioned({'v': 'test4'}, int(res['version']) - 1, True)
    demisto.results('Should not get here. We should fail on setIntegrationContextVersioned')
