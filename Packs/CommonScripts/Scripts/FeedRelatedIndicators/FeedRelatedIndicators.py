import demistomock as demisto
from CommonServerPython import *


def feed_related_indicator():
    indicator = demisto.args()['indicator']
    feed_related_indicators = indicator.get('CustomFields', {}).get('feedrelatedindicators', [])
    ioc_ = list(filter(lambda x: x.get('value'), feed_related_indicators))
    if ioc_:
        ioc_value = ioc_[0].get('value')

    content = []
    results = demisto.searchIndicators(value=ioc_value).get('iocs', [])
    urls = demisto.demistoUrls()
    server_url = urls.get('server', '')
    if results:
        ioc_id = results[0].get('id')

        for item in feed_related_indicators:
            content.append({
                'Value': f"[{item.get('value')}]({server_url}/indicator/{ioc_id})" if item.get('value') else '',
                'Type': item.get('type'),
                'Description': f"[{item.get('description')}]({item.get('description')})"
            })
    else:
        # In case that no related indicators were found, return the table without the link.
        for item in feed_related_indicators:
            content.append({
                'Value': item.get('value', ''),
                'Type': item.get('type'),
                'Description': f"[{item.get('description')}]({item.get('description')})"
            })

    output = tableToMarkdown('Feed Related Indicators', content, ['Type', 'Value', 'Description'], removeNull=True)
    return CommandResults(
        readable_output=output
    )


def main():
    try:
        return_results(feed_related_indicator())
    except Exception as e:
        return_error(f'Failed to execute FeedRelatedIndicatorsWidget. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
