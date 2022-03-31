from CommonServerPython import *

import traceback

COLORS = {'AWS': 'ff0000',
          'GCP': '339966',
          'Azure': '0000ff'}

HTML_START = """<h1 style="color: #2e6c80; height: 170px; line-height: 170px; text-align: center;">"""
HTML = """<span style="color: #{color};"><strong>{provider}&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; </strong></span>"""


''' COMMAND FUNCTION '''


def get_cloudprovider_html_result():
    cloud_providers = get_cloud_providers()
    results = [HTML_START]
    results.extend([HTML.format(provider=provider, color=COLORS.get(provider, '000000')) for provider in cloud_providers])

    html_result = ''.join(results)
    return {'ContentsFormat': EntryFormat.HTML,
            'Type': EntryType.NOTE,
            'Contents': html_result}


def get_cloud_providers():
    incident = demisto.incident()
    xdr_alerts = demisto.get(incident, 'CustomFields.xdralerts')
    if not xdr_alerts:
        raise DemistoException('xdralerts is not configured in the incident')
    if not isinstance(xdr_alerts, list):
        xdr_alerts = [xdr_alerts]
    cloud_providers = {alert.get('cloudprovider') for alert in xdr_alerts}
    return cloud_providers


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
