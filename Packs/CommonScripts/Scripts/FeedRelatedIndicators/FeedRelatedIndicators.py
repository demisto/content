import demistomock as demisto
from CommonServerPython import *


def feed_related_indicator():
    indicator = demisto.get(demisto.args()['indicator'], "CustomFields.feedrelatedindicators")
    for field in indicator:
        ioc_value = field.get('value', '')

    content = []
    results = demisto.searchIndicators(value=ioc_value).get('iocs', [])
    if results:
        for ioc_field in results:
            ioc_id = ioc_field.get('id')
    urls = demisto.demistoUrls()
    server_url = urls.get('server', '')

    for item in indicator:
        content.append({
            'Value': f"[{item.get('value', '')}]({server_url}/indicator/{ioc_id})" if item.get('value') else '',
            'Type': item.get('type'),
            'Description': f"[{item.get('description')}]({item.get('description')})"
        })

    output = tableToMarkdown('Feed Related Indicators', content, ['Value', 'Type', 'Description'], removeNull=True)
    return CommandResults(
        readable_output=output
    )


def main():
    try:
        return_results(feed_related_indicator())
    except Exception as e:
        return_error(f'Error : {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
