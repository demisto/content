import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from distutils.util import strtobool


def indicator_type_finder(indicator_data: dict):
    """Find the indicator type of the given indicator

    Args:
        indicator_data(dict): The data about the indicator

    Returns:
        str. The indicator type
    """
    indicator = indicator_data.get('value')
    # PhishLabs IOC does not classify Email indicators correctly giving them typing of "ReplayTo", "HeaderReplyTo"
    # "ReturnPath" and so on - to combat that we find the Email indicator type by regex
    # returned URLs could fit the email regex at some cases so we exclude them
    if re.match(str(emailRegex), str(indicator)) and str(indicator_data.get('type')).lower() != 'url':
        return 'Email'

    else:
        return indicator_data.get('type')


since = demisto.args().get('since')
delete_false_positive = bool(strtobool(demisto.args().get('delete_false_positive', 'false')))
limit = demisto.args().get('limit')
indicator_type = demisto.args().get('indicator_type')
remove_protocol = demisto.args().get('remove_protocol')
remove_query = demisto.args().get('remove_query')
command_args = {}

if since:
    command_args['since'] = since
if limit:
    command_args['limit'] = int(limit)
if indicator_type:
    command_args['indicator_type'] = indicator_type
if remove_protocol:
    command_args['remove_protocol'] = remove_protocol
if remove_query:
    command_args['remove_query'] = remove_query
if delete_false_positive:
    command_args['false_positive'] = 'true'

entry = demisto.executeCommand('phishlabs-global-feed', command_args)[0]

if isError(entry):
    demisto.results('Failed getting the global feed from PhishLabs - {}'.format(entry['Contents']))
else:
    content = entry.get('Contents')
    if not content or not isinstance(content, dict):
        return_error('No indicators found')

    feed = content.get('data', [])

    if delete_false_positive:
        false_positives = list(filter(lambda f: bool(strtobool(str(f.get('falsePositive', 'false')))) is True, feed))
        for false_positive in false_positives:
            delete_res = demisto.executeCommand('deleteIndicators',
                                                {'query': 'source:"PhishLabs" and value:"{}"'
                                                    .format(false_positive.get('value')),
                                                 'reason': 'Classified as false positive by PhishLabs'})
            if isError(delete_res[0]):
                return_error('Error deleting PhishLabs indicators - {}'.format(delete_res[0]['Contents']))
    else:
        for indicator in feed:
            indicator_type = indicator_type_finder(indicator)
            indicator_value = indicator.get('value')
            indicator_timestamp = None
            if indicator.get('createdAt'):
                indicator_timestamp = datetime.strptime(indicator['createdAt'], '%Y-%m-%dT%H:%M:%SZ')
            if indicator_type == 'Attachment':
                indicator_type = 'File MD5'
                file_md5_attribute = list(filter(lambda f: f.get('name') == 'md5', indicator.get('attributes', [])))
                indicator_value = file_md5_attribute[0].get('value') if file_md5_attribute else ''

            demisto_indicator = {
                'type': indicator_type_finder(indicator),
                'value': indicator_value,
                'source': 'PhishLabs',
                'reputation': 'Bad',
                'seenNow': 'true',
                'comment': 'From PhishLabs Global Feed'
            }

            if indicator_timestamp:
                demisto_indicator['sourceTimeStamp'] = datetime.strftime(indicator_timestamp, '%Y-%m-%dT%H:%M:%SZ')
            indicator_res = demisto.executeCommand('createNewIndicator', demisto_indicator)

            if isError(indicator_res[0]):
                return_error('Error creating indicator - {}'.format(indicator_res[0]['Contents']))

    demisto.results('Successfully populated indicators')
