"""Base Script for Cortex XSOAR (aka Demisto)

This is an empty script with some basic structure according
to the code conventions.

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

"""

from CommonServerPython import *

from typing import Dict, Any
import traceback

COLORS = {'AWS': 'ff0000',
          'GCP': '339966',
          'Azure': '0000ff'}

HTML_START = """<h1 style="color: #2e6c80; height: 170px; line-height: 170px; text-align: center;">"""
HTML = """<span style="color: #{color};"><strong>{provider}&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; </strong></span>"""


''' COMMAND FUNCTION '''


def get_cloudprovider_html_result():
    incident = demisto.incident()
    xdr_alerts = demisto.get(incident, 'CustomFields.xdralerts')
    if not xdr_alerts:
        raise DemistoException('xdralerts is not configured in the incident')
    if not isinstance(xdr_alerts, list):
        xdr_alerts = [xdr_alerts]
    cloud_providers = list(set([alert.get('cloudprovider') for alert in xdr_alerts]))
    results = [HTML_START]
    results.extend([HTML.format(provider=provider, color=COLORS.get(provider)) for provider in cloud_providers])

    html_result = ''.join(results)
    return {'ContentsFormat': EntryFormat.HTML,
            'Type': EntryType.NOTE,
            'Contents': html_result}


''' MAIN FUNCTION '''


def main():
    try:
        return_results(get_cloudprovider_html_result())
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute CloudProviderWidget. Error: {str(ex)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
