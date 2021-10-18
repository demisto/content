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
    cloud_providers = set([alert.get('cloudprovider') for alert in xdr_alerts])
    file_results = []
    if 'GCP' in cloud_providers:
        gcp_file = requests.get(
            'https://user-images.githubusercontent.com/88267954/137717374-79a61096-ec0c-4712-91e6-2338243b0b6b.png',
            verify=False).content

        file_results.append(fileResult('GCP', gcp_file, file_type=EntryType.IMAGE))
    if 'Azure' in cloud_providers:
        azure_file = requests.get(
            'https://user-images.githubusercontent.com/88267954/137730231-6cd195d2-6e79-4969-b625-26e62fcb88a9.png', verify=False).content
        file_results.append(fileResult('Azure', azure_file, file_type=EntryType.IMAGE))
    if 'AWS' in cloud_providers:
        aws_file = requests.get(
            'https://user-images.githubusercontent.com/88267954/137717493-921017d2-e13a-48b0-a2f6-e559cfe8ac8e.png', verify=False).content
        file_results.append(fileResult('AWS', aws_file, file_type=EntryType.IMAGE))
    return file_results


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
