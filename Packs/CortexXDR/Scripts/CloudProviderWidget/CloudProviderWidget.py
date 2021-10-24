"""Base Script for Cortex XSOAR (aka Demisto)

This is an empty script with some basic structure according
to the code conventions.

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

"""

import demistomock as demisto
from CommonServerPython import *

from typing import Dict, Any
import traceback

''' STANDALONE FUNCTION '''


''' COMMAND FUNCTION '''


def get_image_from_alerts() -> CommandResults:
    incident = demisto.incident()
    xdr_alerts = incident.get('CustomFields').get('xdralerts')
    cloud_providers = list(set([alert.get('cloudprovider') for alert in xdr_alerts]))
    return CommandResults(readable_output='\n'.join(cloud_providers))


''' MAIN FUNCTION '''


def main():
    try:
        return_results(get_image_from_alerts())
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute CloudProviderWidget. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
