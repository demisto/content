import demistomock as demisto
from CommonServerPython import *
import sys
# from pprint import pformat

DEMISTO_ARGS = demisto.args()

COMMAND = DEMISTO_ARGS['command']
ENABLED = None
if 'enabled' in DEMISTO_ARGS:
    enabled = DEMISTO_ARGS['enabled']
    if enabled.lower() == 'true':
        ENABLED = True
    elif enabled.lower() == 'false':
        ENABLED = False

integration_commands_args = {
    "uri": "/settings/integration-commands"
}
integration_commands_res = demisto.executeCommand("demisto-api-get", integration_commands_args)


integration_search = None
if ENABLED != None:
    # if we only want to search enabled integrations, we must fetch that list from another API
    integration_search_args = {
        "uri": "/settings/integration/search",
        "body": { "size": 1000 }
    }
    integration_search_res = demisto.executeCommand("demisto-api-post", integration_search_args)
    try:
        integration_search = integration_search_res[0]['Contents']['response']
    except KeyError:
        demisto.error('Did not receive expected response from Demisto API')
        sys.exit()
    #demisto.log(pformat(integration_search))
    #sys.exit()
if integration_search:
    integration_instances = integration_search['instances']
    integration_instances_enabled = {}
    for integration in integration_instances:
        name = integration['brand']
        #demisto.log(pformat(integration))
        if integration['enabled'] == 'true':
            integration_instances_enabled[name] = True



try:
    integration_commands = integration_commands_res[0]['Contents']['response']
except KeyError:
    demisto.error('Did not receive expected response from Demisto API')
    sys.exit()

#demisto.log(pformat(integration_commands))

integrations_that_implement = []

for integration in integration_commands:

    integration_name = integration['display']

    if 'commands' in integration:
        for command in integration['commands']:

            command_name = command['name']
            if command_name == COMMAND:
                if ENABLED == None:
                    integrations_that_implement.append(integration_name)
                elif ENABLED == True and integration_name in integration_instances_enabled:
                    integrations_that_implement.append(integration_name)
                elif ENABLED == False and not integration_name in integration_instances_enabled:
                    integrations_that_implement.append(integration_name)


if len(integrations_that_implement) == 0:
    demisto.results(None)
else:
    demisto.results(','.join(integrations_that_implement))
