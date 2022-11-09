import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

query = demisto.args().get('query')
name = demisto.args().get('name')
investigation_url = demisto.demistoUrls().get('investigation')
use_alt_link = demisto.args().get('use_alt_link') in ['True', 'true']
max_name_characters = int(demisto.args().get('max_name_characters', 40))


def get_base_url(url):
    url = url.split('/')
    domain = url[2]
    protocol = url[0]
    return f'{protocol}//{domain}'


def make_indicator_link(indicator_id, label):
    base_url = get_base_url(investigation_url)
    return f'<a href="{base_url}/#/indicator/{indicator_id}">{label}</a>'


def shorten_name(value):
    return value[:max_name_characters] + '...'


def is_longer_than_max_name_characters(value):
    return len(value) > max_name_characters


def format_score(value):
    color_div = '<div style=\"color:{0};\">{1}</div>'

    scores = {
        0: 'Unknown',
        1: color_div.format('green', 'Benign'),
        2: color_div.format('yellow', 'Suspicious'),
        3: color_div.format('red', 'Malicious')
    }

    return scores.get(value, 'Unknown - Map Error')


def format_indicator_table_alt_link(indicator):
    value = indicator.get('value')
    indicator_id = indicator.get('id')
    return {
        'Name': shorten_name(value) if is_longer_than_max_name_characters(value) else value,
        ' ': make_indicator_link(indicator_id, '<small>Open in XSOAR</small>'),
        'Type': indicator.get('indicator_type'),
        'Score': format_score(indicator.get('score', 0)),
        'Incident Count': indicator.get('relatedIncCount', 0),
        'Last Seen': str(indicator.get('lastSeen', 'First Time Seen'))
    }


def format_indicator_table(indicator):
    value = indicator.get('value')
    indicator_id = indicator.get('id')
    return {
        'Name': make_indicator_link(indicator_id, shorten_name(value) if is_longer_than_max_name_characters(value) else value),
        'Type': indicator.get('indicator_type'),
        'Score': format_score(indicator.get('score', 0)),
        'Incident Count': indicator.get('relatedIncCount', 0),
        'Last Seen': str(indicator.get('lastSeen', 'First Time Seen'))
    }


def make_indicator_table(query, use_alt_link):
    indicators = demisto.searchIndicators(query=query, size=300)['iocs']
    headers = ['Name', ' ', 'Type', 'Score', 'Incident Count', 'Last Seen']

    formatter = format_indicator_table_alt_link if use_alt_link else format_indicator_table

    if indicators:
        indicators = list(map(formatter, indicators))
        indicator_table = demisto.executeCommand(
            'fancy-email-make-table', {'items': indicators, 'headers': headers, 'name': name})[0]['Contents']['html']
        return indicator_table
    return ''


indicator_table = make_indicator_table(query, use_alt_link)
output_text = f"Indicator Table Created in the FancyEmails.IndicatorTable Context - {use_alt_link}"
return_results(CommandResults(outputs_prefix="FancyEmails.IndicatorTable",
                              outputs={'name': name,
                                             'html': indicator_table},
                              readable_output=output_text,
                              )
               )
