import base64
import copy
import hashlib
import hmac
import time
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from enum import Enum
import requests
import urllib.parse

TC_INDICATOR_PATH = 'TC.Indicator(val.ID && val.ID === obj.ID)'
MAX_CONTEXT = 100


class Method(str, Enum):
    """
    A list that represent the types of http request available
    """
    GET = 'GET'
    POST = 'POST'
    PUT = 'PUT'
    HEAD = 'HEAD'
    PATCH = 'PATCH'
    DELETE = 'DELETE'


class Client:
    def __init__(self, api_id: str, api_secret: str, base_url: str, verify: bool = False):
        self.api_id = api_id
        self.api_secret = api_secret
        self.base_url = base_url
        self.verify = verify

    def make_request(self, method: Method, url_suffix: str, payload: dict = {}, params: dict = {}):
        headers = self.create_header(url_suffix, method)

        url = urljoin(self.base_url, url_suffix)
        response = requests.request(method=method, url=url, headers=headers, data=payload, params=params,
                                    verify=self.verify)
        demisto.log(f'The response from the API: \n{response.text}')
        return json.loads(response.text), response.status_code

    def create_header(self, url_suffix: str, method: Method) -> dict:
        timestamp = round(time.time())
        to_sign = f'{url_suffix}:{method}:{timestamp}'
        hash = base64.b64encode(
            hmac.new(self.api_secret.encode('utf8'), to_sign.encode('utf8'), hashlib.sha256).digest()).decode()
        return {'Authorization': f'TC {self.api_id}:{hash}', 'Timestamp': str(timestamp)}


def create_context(indicators, include_dbot_score=False):
    indicators_dbot_score = {}  # type: dict
    params = demisto.params()
    rating_threshold = int(params.get('rating', '3'))
    confidence_threshold = int(params.get('confidence', '3'))
    context = {
        'DBotScore': [],
        outputPaths['ip']: [],
        outputPaths['url']: [],
        outputPaths['domain']: [],
        outputPaths['file']: [],
        TC_INDICATOR_PATH: [],
    }  # type: dict
    tc_type_to_demisto_type = {
        'Address': 'ip',
        'URL': 'url',
        'Host': 'domain',
        'File': 'file'
    }
    type_to_value_field = {
        'Address': 'ip',
        'URL': 'text',
        'Host': 'hostName',
        'File': 'md5'
    }

    for ind in indicators:
        indicator_type = tc_type_to_demisto_type.get(ind['type'], ind['type'])
        value_field = type_to_value_field.get(ind['type'], 'summary')
        value = ind.get(value_field, ind.get('summary', ''))

        if ind.get('confidence') is not None:  # returned in specific indicator request - SDK
            confidence = int(ind['confidence'])
        else:
            # returned in general indicator request - REST API
            confidence = int(ind.get('threatAssessConfidence', 0))

        if ind.get('rating') is not None:  # returned in specific indicator request - SDK
            rating = int(ind['rating'])
        else:
            # returned in general indicator request - REST API
            rating = int(ind.get('threatAssessRating', 0))

        md5 = ind.get('md5')
        sha1 = ind.get('sha1')
        sha256 = ind.get('sha256')

        if confidence >= confidence_threshold and rating >= rating_threshold:
            dbot_score = Common.DBotScore.BAD
            desc = ''
            if hasattr(ind, 'description'):
                desc = ind.description
            mal = {
                'Malicious': {
                    'Vendor': 'ThreatConnect',
                    'Description': desc,
                }
            }
            if indicator_type == 'ip':
                mal['Address'] = value

            elif indicator_type == 'file':
                mal['MD5'] = md5
                mal['SHA1'] = sha1
                mal['SHA256'] = sha256

            elif indicator_type == 'url':
                mal['Data'] = value

            elif indicator_type == 'domain':
                mal['Name'] = value

            context_path = outputPaths.get(indicator_type)
            if context_path is not None:
                context[context_path].append(mal)
        # if both confidence and rating values are less than the threshold - DBOT score is unknown
        elif confidence < confidence_threshold and rating < rating_threshold:
            dbot_score = Common.DBotScore.NONE
        else:
            dbot_score = Common.DBotScore.SUSPICIOUS

        # if there is more than one indicator results - take the one with the highest score
        if include_dbot_score:
            # see explanation in issue #42224
            keys = (value,) if indicator_type != 'file' else filter(None, (md5, sha1, sha256))

            old_val = indicators_dbot_score.get(value)
            if old_val and old_val['Score'] < dbot_score:
                for k in keys:
                    indicators_dbot_score[k]['Score'] = dbot_score

            else:
                dbot_object = {
                    'Indicator': value,
                    'Score': dbot_score,
                    'Type': indicator_type,
                    'Vendor': 'ThreatConnect',
                    'Reliability': demisto.params().get('integrationReliability', 'B - Usually reliable')
                }
                for k in keys:
                    dbot_object = copy.copy(dbot_object)
                    dbot_object['Indicator'] = k
                    indicators_dbot_score[k] = dbot_object

        context[TC_INDICATOR_PATH].append({
            'ID': ind['id'],
            'Name': value,
            'Type': ind['type'],
            'Owner': ind.get('ownerName', ind.get('owner')),
            'Description': ind.get('description'),
            'CreateDate': ind['dateAdded'],
            'LastModified': ind['lastModified'],
            'Rating': rating,
            'Confidence': confidence,
            'WebLink': ind.get('webLink'),

            # relevant for domain
            'Active': ind.get('whoisActive'),

            # relevant for file
            'File.MD5': md5,
            'File.SHA1': sha1,
            'File.SHA256': sha256,
        })

        if 'group_associations' in ind:
            if ind['group_associations']:
                context[TC_INDICATOR_PATH][0]['IndicatorGroups'] = ind['group_associations']

        if 'indicator_associations' in ind:
            if ind['indicator_associations']:
                context[TC_INDICATOR_PATH][0]['IndicatorAssociations'] = ind[
                    'indicator_associations']

        if 'indicator_tags' in ind:
            if ind['indicator_tags']:
                context[TC_INDICATOR_PATH][0]['IndicatorTags'] = ind['indicator_tags']

        if 'indicator_observations' in ind:
            if ind['indicator_observations']:
                context[TC_INDICATOR_PATH][0]['IndicatorsObservations'] = ind[
                    'indicator_observations']

        if 'indicator_attributes' in ind:
            if ind['indicator_attributes']:
                context[TC_INDICATOR_PATH][0]['IndicatorAttributes'] = ind[
                    'indicator_attributes']

    context['DBotScore'] = list(indicators_dbot_score.values())
    context = {k: createContext(v, removeNull=True)[:MAX_CONTEXT] for k, v in context.items() if v}
    return context, context.get(TC_INDICATOR_PATH, [])


def tc_get_group(client: Client) -> list:
    group_id = demisto.args().get('group_id')
    response, status_code = client.make_request(Method.GET, f'/api/v3/groups/{group_id}', params={})
    if status_code != 200:
        return_error(response.text)
    group = response.get('data')
    return_outputs(
        tableToMarkdown(group),
        group,
        response
    )


def get_indicators(client: Client, args_type: str, type_name: str) -> list:
    args = demisto.args()
    owners_query = create_or_query(args.get('owners', demisto.params().get('defaultOrg')), 'ownerName')
    query = create_or_query(args.get(args_type), 'summary')
    rating_threshold = args.get('ratingThreshold', '')
    confidence_threshold = args.get('confidenceThreshold', '')
    indicators = []

    if rating_threshold:
        rating_threshold = f'AND (rating > {rating_threshold}) '
    if confidence_threshold:
        confidence_threshold = f'AND (confidence > {confidence_threshold}) '
    tql = f'typeName EQ "{type_name}" AND ({owners_query}) AND ({query}{confidence_threshold}{rating_threshold})'
    tql = urllib.parse.quote(tql.encode('utf8'))
    url = f'/api/v3/indicators?tql={tql}&resultStart=0&resultLimit=1000'

    while True:
        response, status_code = client.make_request(Method.GET, url)
        if status_code != 200:
            return_error(response.text)
        indicators.extend(response.get('data'))
        if 'next' in response:
            url = str(response.get('next')).replace(client.base_url, '')
        else:
            break
    ec, indicators = create_context(indicators, include_dbot_score=True)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': indicators,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('ThreatConnect URL Reputation for: {}'.format(args.get(args_type)), indicators,
                                         headerTransform=pascalToSpace),
        'EntryContext': ec
    })


def create_or_query(delimitered_str: str, param_name: str) -> str:
    arr = delimitered_str.split(',')
    query = ''
    for item in arr:
        query += f'{param_name}="{item}" OR '
    return query[:len(query) - 3]


def get_ip_indicators(client: Client) -> list:
    return get_indicators(client, 'ips', 'Address')


def get_url_indicators(client: Client) -> list:
    return get_indicators(client, 'urls', 'URL')


def get_domain_indicators(client: Client) -> list:
    return get_indicators(client, 'domains', 'Host')


def get_file_indicators(client: Client) -> list:
    return get_indicators(client, 'files', 'File')


def tc_delete_group_command(client: Client) -> Any:
    args = demisto.args()
    group_id = args.get('groupID')
    group_type = args.get('type')
    tql = f'typeName EQ "{group_type}"'
    tql = urllib.parse.quote(tql.encode('utf8'))
    url = f'/api/v3/groups/{group_id}?tql={tql}'
    response, status_code = client.make_request(Method.DELETE, url)
    if status_code == 200 and response.get('status') == 'Success':
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['text'],
            'Contents': '{} {} deleted Successfully'.format(group_type.lower(), group_id)
        })
    else:
        return_error('Failed to delete {} {}'.format(group_type, group_id))


def tc_get_indicators_command(client: Client) -> Any:
    args = demisto.args()
    owners_query = create_or_query(args.get('owner', demisto.params().get('defaultOrg')), 'ownerName')
    limit = args.get('limit', '500')
    page = args.get('page', '0')
    tql = f'{owners_query}'
    tql = urllib.parse.quote(tql.encode('utf8'))
    url = f'/api/v3/indicators?tql={tql}&resultStart={page}&resultLimit={limit}'

    response, status_code = client.make_request(Method.GET, url)
    if status_code != 200:
        return_error(response.text)
    indicators = response.get('data')

    ec, indicators = create_context(indicators, include_dbot_score=True)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': response,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('ThreatConnect Indicators:', indicators, headerTransform=pascalToSpace),
        'EntryContext': ec
    })


def tc_get_owners_command(client: Client) -> Any:
    url = f'/api/v3/security/owners'

    response, status_code = client.make_request(Method.GET, url)
    if status_code != 200:
        return_error(response.text)
    raw_owners = response.get('data')
    owners = []
    for owner in raw_owners:
        owners.append({
            'ID': owner['id'],
            'Type': owner['type'],
            'Name': owner['name']
        })

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': raw_owners,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('ThreatConnect Owners:', owners),
        'EntryContext': {'TC.Owner(val.ID && val.ID === obj.ID)': owners}
    })


def tc_get_indicator_owners(client: Client) -> Any:
    args = demisto.args()
    indicator_type = args.get('indicatorType')
    indicator = args.get('indicator')
    url = f'/api/v2/indicators/{indicator_type}/{urllib.parse.quote(indicator.encode("utf8"))}/owners'
    owners = []
    owners_raw, status_code = client.make_request(Method.GET, url)
    if 'status' in owners_raw:
        if owners_raw['status'] == 'Success':
            if len(owners_raw['data']['owner']) > 0:
                owners = owners_raw['data']['owner']
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': owners_raw,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('ThreatConnect Owners for Indicator:' + demisto.args()['indicator'], owners),
        'EntryContext': {'TC.Owners': owners}
    })


COMMANDS = {
    #     'test-module': test_integration,
    'ip': get_ip_indicators,
    'url': get_url_indicators,
    'file': get_file_indicators,
    'domain': get_domain_indicators,
    #
    'tc-owners': tc_get_owners_command,
    'tc-indicators': tc_get_indicators_command,
    #     'tc-get-tags': tc_get_tags_command,
    #     'tc-tag-indicator': tc_tag_indicator_command,
    #     'tc-get-indicator': tc_get_indicator_command,
    #     'tc-get-indicators-by-tag': tc_get_indicators_by_tag_command,
    #     'tc-add-indicator': tc_add_indicator_command,
    #
    #     'tc-create-incident': tc_create_incident_command,
    #     'tc-fetch-incidents': tc_fetch_incidents_command,
    #     'tc-get-incident-associate-indicators': tc_get_incident_associate_indicators_command,
    #     'tc-incident-associate-indicator': tc_incident_associate_indicator_command,
    #     'tc-update-indicator': tc_update_indicator_command,
    #     'tc-delete-indicator': tc_delete_indicator_command,
    #     'tc-delete-indicator-tag': tc_delete_indicator_tag_command,
    #     'tc-create-campaign': tc_create_campaign_command,
    #     'tc-create-event': tc_create_event_command,
    #     'tc-get-events': tc_get_events,
    #     'tc-add-group-attribute': tc_add_group_attribute,
    #     'tc-create-threat': tc_create_threat_command,
    'tc-delete-group': tc_delete_group_command,
    'tc-get-group': tc_get_group,
    #     'tc-add-group-security-label': add_group_security_label,
    #     'tc-add-group-tag': add_group_tag,
    #     'tc-get-indicator-types': tc_get_indicator_types,
    #     'tc-group-associate-indicator': associate_indicator,
    #     'tc-create-document-group': create_document_group,
    #     'tc-get-group': get_group,
    #     'tc-get-group-attributes': get_group_attributes,
    #     'tc-get-group-security-labels': get_group_security_labels,
    #     'tc-get-group-tags': get_group_tags,
    #     'tc-download-document': download_document,
    #     'tc-get-group-indicators': get_group_indicator,
    #     'tc-get-associated-groups': get_group_associated,
    #     'tc-associate-group-to-group': associate_group_to_group,
    'tc-get-indicator-owners': tc_get_indicator_owners,
    #     'tc-download-report': tc_download_report,
}


def main(params):
    try:
        insecure = not params.get('insecure')
        client = Client(params.get('accessId'), params.get('secretKey'), params.get('baseUrl'), insecure)
        command = demisto.command()
        demisto.log('command is %s' % (demisto.command(),))
        if command in COMMANDS.keys():
            COMMANDS[command](client)

    except Exception as e:
        raise e
        print(f'error has occurred: {str(e)}')
        # return_error(f'error has occurred: {str(e)}', error=e)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main(demisto.params())
