import demistomock as demisto
from CommonServerPython import *


def create_related_indicator_object(value: str, type_: str, description: str):
    """Creates a related indicator object to be added to table.

    Args:
        value (str): object value.
        type_ (str): object type.
        description (str): object description.

    Returns:
        Dict. Related indicator object.
    """
    indicator_object = {
        'Value': value,
        'Type': type_
    }

    descriptions = []

    for desc in description.split(','):
        desc = desc.strip()

        if re.match(urlRegex, desc):
            descriptions.append(f'[{desc}]({desc})')
        else:
            descriptions.append(desc)

    indicator_object['Description'] = f"{', '.join(descriptions)}\n\n"

    return indicator_object



def feed_related_indicator(args) -> CommandResults:
    indicator = args['indicator']
    feed_related_indicators = indicator.get('CustomFields', {}).get('feedrelatedindicators', [])
    ioc = list(filter(lambda x: x.get('value'), feed_related_indicators))
    ioc_value = ioc[0].get('value') if ioc else ''

    content = []
    results = demisto.searchIndicators(value=ioc_value).get('iocs', [])
    urls = demisto.demistoUrls()
    server_url = urls.get('server', '')
    if results:
        ioc_id = results[0].get('id')

        for item in feed_related_indicators:
            content.append(create_related_indicator_object(
                f"[{item.get('value')}]({server_url}/#/indicator/{ioc_id})" if item.get('value') else '',
                item.get('type'),
                item.get('description')
            ))
    else:
        # In case that no related indicators were found, return the table without the link.
        for item in feed_related_indicators:
            content.append(create_related_indicator_object(
                item.get('value', ''),
                item.get('type'),
                item.get('description')
            ))

    output = tableToMarkdown('', content, ['Type', 'Value', 'Description'], removeNull=True)
    return CommandResults(readable_output=output)


def main(args):
    try:
        return_results(feed_related_indicator(args))
    except Exception as e:
        return_error(f'Failed to execute FeedRelatedIndicatorsWidget. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main(demisto.args())
