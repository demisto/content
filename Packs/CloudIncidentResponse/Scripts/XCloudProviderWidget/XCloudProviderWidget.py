import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


COLORS = {'AWS': 'ff0000',
          'GCP': '339966',
          'Azure': '0000ff'}

HTML_START = """<h1 style="color: #2e6c80; height: 170px; line-height: 170px; text-align: center;">"""
HTML = """<span style="color: #{color};"><strong>{provider}&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; </strong></span>"""


''' COMMAND FUNCTION '''


def get_cloudprovider_html_result():
    cloud_providers = get_cloud_providers()
    results = [HTML_START]
    results.extend([HTML.format(provider=cloud_providers, color=COLORS.get(cloud_providers, '000000'))])

    html_result = ''.join(results)
    return {'ContentsFormat': EntryFormat.HTML,
            'Type': EntryType.NOTE,
            'Contents': html_result}


def get_cloud_providers():
    incident = demisto.incident()
    cloud_providers = incident.get('CustomFields', {}).get('cloudprovider', ['N/A'])[0]
    return cloud_providers


''' MAIN FUNCTION '''


def main():
    try:
        return_results(get_cloudprovider_html_result())
    except Exception as ex:
        return_error(f'Failed to execute CloudProviderWidget. Error: {str(ex)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
