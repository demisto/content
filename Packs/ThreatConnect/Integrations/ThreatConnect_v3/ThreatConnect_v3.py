import copy
import hashlib
import hmac
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

    def make_request(self, method: Method, url_suffix: str, payload: dict = {}, params: dict = {},
                     parse_json=True, content_type=None):  # pragma: no cover # noqa # type: ignore
        headers = self.create_header(url_suffix, method)
        if content_type:
            headers['Content-Type'] = content_type
        url = urljoin(self.base_url, url_suffix)
        response = requests.request(method=method, url=url, headers=headers, data=payload, params=params,
                                    verify=self.verify)
        if parse_json:
            return json.loads(response.text), response.status_code
        return response

    def create_header(self, url_suffix: str, method: Method) -> dict:
        timestamp = round(time.time())
        to_sign = f'{url_suffix}:{method}:{timestamp}'
        hash = base64.b64encode(
            hmac.new(self.api_secret.encode('utf8'), to_sign.encode('utf8'), hashlib.sha256).digest()).decode()
        return {'Authorization': f'TC {self.api_id}:{hash}', 'Timestamp': str(timestamp),
                'Content-Type': 'application/json'}


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


def get_indicators(client: Client, args_type: str, type_name: str) -> None:  # pragma: no cover
    args = demisto.args()
    owners_query = create_or_query(args.get('owners', demisto.params().get('defaultOrg')), 'ownerName')
    query = create_or_query(args.get(args_type), 'summary')
    rating_threshold = args.get('ratingThreshold', '')
    confidence_threshold = args.get('confidenceThreshold', '')

    if rating_threshold:
        rating_threshold = f'AND (rating > {rating_threshold}) '
    if confidence_threshold:
        confidence_threshold = f'AND (confidence > {confidence_threshold}) '
    if owners_query:
        owners_query = f'AND ({owners_query}) '
    tql = f'typeName EQ "{type_name}" {owners_query}AND ({query}{confidence_threshold}{rating_threshold})'
    tql = urllib.parse.quote(tql.encode('utf8'))
    url = f'/api/v3/indicators?tql={tql}&resultStart=0&resultLimit=1000'

    response, status_code = client.make_request(Method.GET, url)
    if status_code != 200:
        return_error('Error from the API: ' + response.get('message',
                                                           'An error has occurred if it persist please contact your '
                                                           'local help desk'))
    indicators = response.get('data')

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


def create_or_query(delimiter_str: str, param_name: str, wrapper: str = '"') -> str:
    if not delimiter_str:
        return ''
    arr = delimiter_str.split(',')
    query = ''
    for item in arr:
        query += f'{param_name}={wrapper}{item}{wrapper} OR '
    return query[:len(query) - 3]


def get_ip_indicators(client: Client):  # pragma: no cover
    return get_indicators(client, 'ips', 'Address')


def get_url_indicators(client: Client):  # pragma: no cover
    return get_indicators(client, 'urls', 'URL')


def get_domain_indicators(client: Client):  # pragma: no cover
    return get_indicators(client, 'domains', 'Host')


def get_file_indicators(client: Client):
    return get_indicators(client, 'files', 'File')


def tc_delete_group_command(client: Client) -> Any:  # pragma: no cover
    args = demisto.args()
    group_ids = args.get('groupID').split(',')
    for id in group_ids:
        url = f'/api/v3/groups/{id}'
        client.make_request(Method.DELETE, url)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': '{} was deleted Successfully'.format(group_ids)
    })


def tc_get_indicators_command(client: Client, confidence_threshold: str = '', rating_threshold: str = '',
                              tag: str = '', owners: str = '', indicator_id: str = '', indicator_type: str = '',
                              return_raw=False, group_associations: str = 'false',
                              indicator_associations: str = 'false',
                              indicator_observations: str = 'false', indicator_tags: str = 'false',
                              indicator_attributes: str = 'false') -> Any:  # pragma: no cover
    args = demisto.args()
    owners = args.get('owner', owners)
    limit = args.get('limit', '500')
    page = args.get('page', '0')
    tag = args.get('tag', tag)
    indicator_type = args.get('type', indicator_type)
    indicator_id = args.get('id', indicator_id)
    rating_threshold = args.get('ratingThreshold', rating_threshold)
    confidence_threshold = args.get('confidenceThreshold', confidence_threshold)

    indicator_attributes = args.get('indicator_attributes', indicator_attributes)
    indicator_tags = args.get('indicator_tags', indicator_tags)
    indicator_observations = args.get('indicator_observations', indicator_observations)
    indicator_associations = args.get('indicator_associations', indicator_associations)
    group_associations = args.get('group_associations', group_associations)
    tql = ''
    tql_prefix = ''
    if rating_threshold:
        rating_threshold = f'AND (rating > {rating_threshold}) '
        tql_prefix = '?tql='
    if confidence_threshold:
        confidence_threshold = f'AND (confidence > {confidence_threshold}) '
        tql_prefix = '?tql='
    if tag:
        tag = f' AND tag LIKE "%{tag}%"'
        indicator_tags = 'true'
        tql_prefix = '?tql='
    if indicator_type:
        indicator_type = f' AND typeName EQ "{indicator_type}"'
        tql_prefix = '?tql='
    if owners:
        owners = ' AND ' + create_or_query(args.get('owner', owners), 'ownerName')
        tql_prefix = '?tql='
    if indicator_id:
        indicator_id = ' AND ' + create_or_query(args.get('id', indicator_id), 'id').replace('"', '')
        tql_prefix = '?tql='
    fields = set_fields({'associatedGroups': group_associations, 'associatedIndicators': indicator_associations,
                         'observations': indicator_observations, 'tags': indicator_tags,
                         'attributes': indicator_attributes})
    tql = f'{indicator_id}{indicator_type}{owners}{tag}{confidence_threshold}{rating_threshold}'.replace(' AND ', '', 1)
    tql = urllib.parse.quote(tql.encode('utf8'))
    url = f'/api/v3/indicators{tql_prefix}{tql}{fields}&resultStart={page}&resultLimit={limit}'
    if not tql_prefix:
        url = url.replace('&', '?', 1)
    response, status_code = client.make_request(Method.GET, url)
    if status_code != 200:
        return_error('Error from the API: ' + response.get('message',
                                                           'An error has occurred if it persist please contact your '
                                                           'local help desk'))
    if return_raw:
        return response, status_code
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


def tc_get_owners_command(client: Client) -> Any:  # pragma: no cover
    url = '/api/v3/security/owners'

    response, status_code = client.make_request(Method.GET, url)
    if status_code != 200:
        return_error('Error from the API: ' + response.get('message',
                                                           'An error has occurred if it persist please contact your '
                                                           'local help desk'))
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


def tc_get_indicator_owners(client: Client) -> Any:  # pragma: no cover
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


def get_group_associated_groups(client: Client) -> Any:  # pragma: no cover
    response, status_code = list_groups(client, include_associated_groups='true', return_raw=True)
    headers = ['GroupID', 'Name', 'Type', 'OwnerName', 'DateAdded']
    if status_code != 200:
        return_error('Error from the API: ' + response.get('message',
                                                           'An error has occurred if it persist please contact your '
                                                           'local help desk'))
    data = response.get('data', [])
    contents = []
    if response.get('status') == 'Success':
        # We get the group by a unique id, so we'll always get one result
        for group in data[0].get('associatedGroups').get('data', []):
            contents.append({
                'GroupID': group.get('id'),
                'Name': group.get('name'),
                'Type': group.get('type'),
                'DateAdded': group.get('dateAdded'),
                'OwnerName': group.get('ownerName')
            })

    else:
        return_error('Error from the API: ' + response.get('message',
                                                           'An error has occurred if it persist please contact your '
                                                           'local help desk'))

    context = {
        'TC.Group.AssociatedGroup(val.GroupID && val.GroupID === obj.GroupID)': contents
    }

    return_outputs(
        tableToMarkdown('ThreatConnect Associated Groups', contents, headers, removeNull=True),
        context,
        response
    )


def test_integration(client: Client) -> None:  # pragma: no cover
    url = '/api/v3/groups?Limit=1'
    response, status_code = client.make_request(Method.GET, url)
    if status_code == 200:
        demisto.results('ok')
    else:
        return_error('Error from the API: ' + response.get('message',
                                                           'An error has occurred if it persist please contact your '
                                                           'local help desk'))


def tc_fetch_incidents_command(client: Client) -> None:  # pragma: no cover
    response, status_code = list_groups(client, group_type='Incident', include_tags='true', include_attributes='true',
                                        return_raw=True)
    if status_code != 200:
        return_error('Error from the API: ' + response.get('message',
                                                           'An error has occurred if it persist please contact your '
                                                           'local help desk'))
    groups = (response.get('data'))

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': groups,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Incidents:', groups, headerTransform=pascalToSpace),
        'EntryContext': {
            'TC.Incident(val.ID && val.ID === obj.ID)': createContext(groups, removeNull=True),
            'ThreatConnect.incidents': groups  # backward compatible
        }
    })


def tc_get_incident_associate_indicators_command(client: Client) -> None:  # pragma: no cover
    response, status_code = list_groups(client, group_type='Incident', include_associated_indicators='true',
                                        return_raw=True)
    if status_code != 200:
        return_error('Error from the API: ' + response.get('message',
                                                           'An error has occurred if it persist please contact your '
                                                           'local help desk'))
    groups = (response.get('data'))
    if not groups:
        return_error('No incident groups were found for the given arguments')
    ec, indicators = create_context(groups[0].get('associatedIndicators', {}).get('data', []),
                                    include_dbot_score=True)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': groups,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Incident Associated Indicators:', indicators, headerTransform=pascalToSpace),
        'EntryContext': ec
    })


def tc_get_events(client: Client) -> None:  # pragma: no cover
    response, status_code = list_groups(client, group_type='Event', return_raw=True)
    if status_code != 200:
        return_error('Error from the API: ' + response.get('message',
                                                           'An error has occurred if it persist please contact your '
                                                           'local help desk'))

    content = []
    headers = ['ID', 'Name', 'OwnerName', 'EventDate', 'DateAdded', 'Status', 'Tags', 'AssociatedIndicators',
               'AssociatedGroups']

    for event in response.get('data'):
        content.append({
            'ID': event.get('id'),
            'Name': event.get('name'),
            'OwnerName': event.get('ownerName'),
            'DateAdded': event.get('dateAdded'),
            'EventDate': event.get('eventDate'),
            'Status': event.get('status'),
            'Tags': event.get('tags'),
            'AssociatedIndicators': event.get('associatedIndicators'),
            'AssociatedGroups': event.get('associatedGroups'),
        })
    context = {
        'TC.Event(val.ID && val.ID === obj.ID)': content
    }

    return_outputs(
        tableToMarkdown('ThreatConnect Events', content, headers, removeNull=True),
        context,
        response
    )


def tc_create_event_command(client: Client) -> None:  # pragma: no cover
    args = demisto.args()
    tags = args.get('tag')
    description = args.get('description', '')
    status = args.get('status', 'New')
    group_type = 'Event'
    event_date = args.get('eventDate', '')
    name = args.get('name')
    tags_list = []
    if tags:
        for tag in tags.split(','):
            tags_list.append({'name': tag})

    payload = json.dumps({
        "type": group_type,
        "name": name,
        "eventDate": event_date,
        "status": status,
        "tags": {
            "data": tags_list
        },
        "body": description
    })
    url = '/api/v3/groups'
    response, status_code = client.make_request(Method.POST, url, payload=payload)  # type: ignore
    if status_code != 201:
        return_error('Error from the API: ' + response.get('message',
                                                           'An error has occurred if it persist please contact your '
                                                           'local help desk'))

    ec = {
        'ID': response.get('data', {}).get('id'),
        'Name': response.get('data', {}).get('name'),
        'Owner': response.get('data', {}).get('ownerName'),
        'Date': response.get('data', {}).get('eventDate'),
        'Tags': response.get('data', {}).get('tags'),
        'Status': response.get('data', {}).get('status'),
        'Type': response.get('data', {}).get('type'),
    }
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': json.dumps(response.get('data')),
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': f'Incident {name} with ID {ec.get("ID")} Created Successfully',
        'EntryContext': {
            'TC.Event(val.ID && val.ID === obj.ID)': createContext([ec], removeNull=True)
        }
    })


def set_fields(fields) -> str:  # pragma: no cover
    fields_str = ''
    if fields.get('include_all_metadata', None):
        return '&fields=tags&fields=associatedIndicators&fields=associatedGroups&fields=securityLabels'
    del fields['include_all_metadata']
    for arg in fields:
        if fields[arg] and fields[arg] != 'false':
            fields_str += f'&fields={arg}'
    return fields_str


def list_groups(client: Client, group_id: str = '', from_date: str = '', tag: str = '', security_label: str = '',
                group_type: str = '', tql_filter: str = '', include_security_labels: str = '',
                include_attributes: str = '',
                include_tags: str = '', include_associated_groups: str = '', include_associated_indicators: str = '',
                include_all_metadata: str = '',
                return_raw=False) -> Any:  # pragma: no cover
    args = demisto.args()
    # FIELDS PARAMS
    include_all_metadata = args.get('include_all_metadata', include_all_metadata)
    include_associated_indicators = args.get('include_associated_indicators', include_associated_indicators)
    include_associated_groups = args.get('include_associated_groups', include_associated_groups)
    include_attributes = args.get('include_attributes', include_attributes)
    include_security_labels = args.get('include_security_labels', include_security_labels)
    include_tags = args.get('include_tags', include_tags)
    # TQL PARAMS
    group_id = args.get('id', group_id)
    from_date = args.get('fromDate', from_date)
    tag = args.get('tag', tag)
    security_label = args.get('security_label', security_label)
    group_type = args.get('group_type', group_type)
    tql_filter = args.get('filter', tql_filter)
    # PAGINATION PARAMS
    limit = args.get('limit', '500')
    page = args.get('page', '0')

    tql_prefix = ''
    tql = ''
    if from_date:
        from_date = f' AND eventDate > "{from_date}" '
        tql_prefix = '?tql='
    if group_type:
        group_type = f' AND typeName EQ "{group_type}"'
        tql_prefix = '?tql='
    if security_label:
        security_label = f' AND securityLabel like "%{security_label}%"'
        tql_prefix = '?tql='
        include_security_labels = 'True'
    if tag:
        tag = f' AND tag like "%{tag}%"'
        tql_prefix = '?tql='
        include_tags = 'true'
    if tql_filter:
        tql_filter = f' AND {tql_filter}'
        tql_prefix = '?tql='
    if group_id:
        group_id = f' AND ({create_or_query(group_id, "id", "")})'
        tql_prefix = '?tql='
    fields = set_fields({'tags': include_tags, 'securityLabels': include_security_labels,
                         'attributes': include_attributes,
                         'associatedGroups': include_associated_groups,
                         'associatedIndicators': include_associated_indicators,
                         'include_all_metadata': include_all_metadata})
    if tql_prefix:
        tql = f'{tql_filter}{group_id}{group_type}{from_date}{tag}{security_label}'.replace(' AND ', '', 1)
        tql = urllib.parse.quote(tql.encode('utf8'))
        tql = f'?tql={tql}'
    url = f'/api/v3/groups{tql}{fields}&resultStart={page}&resultLimit={limit}'
    if not tql_prefix:
        url = url.replace('&', '?', 1)

    response, status_code = client.make_request(Method.GET, url)
    if status_code != 200:
        return_error('Error from the API: ' + response.get('message',
                                                           'An error has occurred if it persist please contact your '
                                                           'local help desk'))
    if return_raw:
        return response, status_code
    content = []
    headers = ['ID', 'Name', 'OwnerName', 'EventDate', 'DateAdded', 'Status', 'Tags', 'AssociatedIndicators',
               'AssociatedGroups', 'securityLabels']

    for group in response.get('data'):
        content.append({
            'ID': group.get('id'),
            'Name': group.get('name'),
            'OwnerName': group.get('ownerName'),
            'DateAdded': group.get('dateAdded'),
            'EventDate': group.get('eventDate'),
            'Status': group.get('status'),
            'Tags': group.get('tags'),
            'AssociatedIndicators': group.get('associatedIndicators'),
            'AssociatedGroups': group.get('associatedGroups'),
            'securityLabels': group.get('securityLabels'),
        })
    context = {
        'TC.Groups(val.ID && val.ID === obj.ID)': content
    }

    return_outputs(
        tableToMarkdown(f'ThreatConnect {group_type} Groups', content, headers, removeNull=True),
        context,
        response
    )


def tc_get_tags_command(client: Client) -> None:  # pragma: no cover
    args = demisto.args()
    limit = args.get('limit', '500')
    page = args.get('page', '0')
    name = args.get('name', '')

    if name:
        name = 'tql=' + urllib.parse.quote(f'summary EQ "{name}" &'.encode('utf8'))

    url = f'/api/v3/tags?{name}resultStart={page}&resultLimit={limit}'
    response, status_code = client.make_request(Method.GET, url)
    if status_code != 200:
        return_error('Error from the API: ' + response.get('message',
                                                           'An error has occurred if it persist please contact your '
                                                           'local help desk'))
    tags = [t['name'] for t in response.get('data')]

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': json.dumps(response),
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('ThreatConnect Tags:', tags, headers='Name'),
        'EntryContext': {'TC.Tags': tags}
    })


def tc_get_indicator_types(client: Client) -> None:  # pragma: no cover
    url = '/api/v2/types/indicatorTypes'
    content = []
    response, status_code = client.make_request(Method.GET, url)
    if status_code != 200:
        return_error('Error from the API: ' + response.get('message',
                                                           'An error has occurred if it persist please contact your '
                                                           'local help desk'))
    headers = ['Name', 'Custom', 'Parsable', 'ApiBranch', 'CasePreference', 'value1Label', 'Value1Type']

    for indicator_type in response.get('data', {}).get('indicatorType', []):
        content.append({
            'Custom': indicator_type.get('custom'),
            'Name': indicator_type.get('name'),
            'Parsable': indicator_type.get('parsable'),
            'ApiBranch': indicator_type.get('apiBranch'),
            'ApiEntity': indicator_type.get('apiEntity'),
            'CasePreference': indicator_type.get('casePreference'),
            'Value1Label': indicator_type.get('value1Label'),
            'Value1Type': indicator_type.get('value1Type')
        })
    context = {
        'TC.IndicatorType(val.Name && val.Name === obj.Name)': content
    }
    return_outputs(
        tableToMarkdown('ThreatConnect indicator types', content, headers, removeNull=True),
        context,
        response
    )


def tc_get_indicators_by_tag_command(client: Client) -> None:  # pragma: no cover
    response, status_code = tc_get_indicators_command(client, return_raw=True)
    ec, indicators = create_context(response.get('data'), include_dbot_score=True)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': indicators,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('ThreatConnect Indicators with tag: {}'.format(demisto.args().get('tag')),
                                         indicators,
                                         headerTransform=pascalToSpace),
        'EntryContext': ec
    })


def tc_get_indicator_command(client: Client) -> None:  # pragma: no cover
    response, status_code = tc_get_indicators_command(client, return_raw=True)
    ec, indicators = create_context(response.get('data'), include_dbot_score=True)
    include_attributes = response.get('data')[0].get('attributes')
    include_observations = response.get('data')[0].get('observations')
    include_tags = response.get('data')[0].get('tags')
    associated_indicators = response.get('data')[0].get('associatedIndicators')
    associated_groups = response.get('data')[0].get('associatedGroups')

    if ec == []:
        ec = {}
    if ec:
        indicators = copy.deepcopy(ec)
        indicators = indicators['TC.Indicator(val.ID && val.ID === obj.ID)']

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': response,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('ThreatConnect indicator for: {}'.format(demisto.args().get('id', '')),
                                         indicators,
                                         headerTransform=pascalToSpace),
        'EntryContext': ec
    })

    if associated_groups:
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': associated_groups.get('data', []),
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown(
                'ThreatConnect Associated Groups for indicator: {}'.format(demisto.args().get('id', '')),
                associated_groups.get('data', []),
                headerTransform=pascalToSpace)
        })

    if associated_indicators:
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': associated_indicators.get('data', []),
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown(
                'ThreatConnect Associated Indicators for indicator: {}'.format(demisto.args().get('id', '')),
                associated_indicators.get('data', []),
                headerTransform=pascalToSpace)
        })

    if include_tags:
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': include_tags.get('data', []),
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown(
                'ThreatConnect Tags for indicator: {}'.format(demisto.args().get('id', '')),
                include_tags.get('data', []),
                headerTransform=pascalToSpace)
        })

    if include_attributes:
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': include_attributes.get('data', []),
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown(
                'ThreatConnect Attributes for indicator: {}'.format(demisto.args().get('id', '')),
                include_attributes.get('data', []),
                headerTransform=pascalToSpace)
        })

    if include_observations is not None:
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': include_observations,
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown(
                'ThreatConnect Observations for indicator: {}'.format(demisto.args().get('id', '')),
                include_observations,
                headerTransform=pascalToSpace)
        })


def tc_delete_indicator_command(client: Client) -> None:  # pragma: no cover
    args = demisto.args()
    indicator_id = args.get('indicatorId')
    url = f'/api/v3/indicators/{indicator_id}'
    response, status_code = client.make_request(Method.DELETE, url)
    if status_code != 200:
        return_error('Error from the API: ' + response.get('message',
                                                           'An error has occurred if it persist please contact your '
                                                           'local help desk'))
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': 'Indicator {} removed Successfully'.format(indicator_id)
    })


def create_document_group(client: Client) -> None:  # pragma: no cover
    name = demisto.args().get('name')
    security_label = demisto.args().get('securityLabel')
    description = demisto.args().get('description', '')
    response, status = create_group(client, security_labels=security_label, name=name, group_type='Document',
                                    description=description)
    res = demisto.getFilePath(demisto.args().get('entry_id'))
    f = open(res['path'], 'rb')
    contents = f.read()
    url = f'/api/v3/groups/{response.get("data").get("id")}/upload'
    payload = f"{contents}"
    client.make_request(Method.POST, url, payload=payload, content_type='application/octet-stream')

    content = {
        'ID': response.get('data').get('id'),
        'Name': response.get('data').get('name'),
        'Owner': response.get('data').get('ownerName', ''),
        'EventDate': response.get('data').get('eventDate', ''),
        'Description': description,
        'SecurityLabel': security_label
    }
    context = {
        'TC.Group(val.ID && val.ID === obj.ID)': content
    }
    return_outputs(tableToMarkdown('ThreatConnect document group was created successfully', content, removeNull=True),
                   context,
                   response.get('data'))


def tc_create_threat_command(client: Client) -> None:  # pragma: no cover
    response, status_code = create_group(client, group_type='Threat')

    ec = {
        'ID': response.get('data', {}).get('id'),
        'Name': response.get('data', {}).get('name'),
        'Owner': response.get('data', {}).get('ownerName'),
        'FirstSeen': response.get('data', {}).get('FirstSeen'),
        'Tag': demisto.args().get('tags'),
        'SecurityLabel': demisto.args().get('securityLabel'),
    }
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': response,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': f'Threat {demisto.args().get("name")} Created Successfully with id: {response.get("data").get("id")}',
        # type: ignore  # noqa
        'EntryContext': {
            'TC.Threat(val.ID && val.ID === obj.ID)': createContext([ec], removeNull=True)
        }
    })


def tc_create_campaign_command(client: Client) -> None:  # pragma: no cover
    response, status_code = create_group(client, group_type='Campaign')

    ec = {
        'ID': response.get('data', {}).get('id'),
        'Name': response.get('data', {}).get('name'),
        'Owner': response.get('data', {}).get('ownerName'),
        'FirstSeen': response.get('data', {}).get('FirstSeen'),
        'Tag': demisto.args().get('tags'),
        'SecurityLabel': demisto.args().get('securityLabel'),
    }
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': response,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': f'Campaign {demisto.args().get("name")} Created Successfully with id: {response.get("data").get("id")}',
        # type: ignore  # noqa
        'EntryContext': {
            'TC.Campaign(val.ID && val.ID === obj.ID)': createContext([ec], removeNull=True)
        }
    })


def tc_create_incident_command(client: Client) -> None:  # pragma: no cover
    response, status_code = create_group(client, group_type='Incident')

    ec = {
        'ID': response.get('data', {}).get('id'),
        'Name': response.get('data', {}).get('name'),
        'Owner': response.get('data', {}).get('ownerName'),
        'EventDate': response.get('data', {}).get('eventDate'),
        'Tag': demisto.args().get('tags'),
        'SecurityLabel': demisto.args().get('securityLabel'),
    }
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': response,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': f'Incident {demisto.args().get("name")} Created Successfully with id: {response.get("data").get("id")}',
        # type: ignore  # noqa
        'EntryContext': {
            'TC.Incident(val.ID && val.ID === obj.ID)': createContext([ec], removeNull=True)
        }
    })


def create_group(client: Client, name: str = '', event_date: str = '', group_type: str = '',
                 status: str = 'New', description: str = '', security_labels: str = '',
                 tags: list = [], first_seen: str = ''):  # pragma: no cover
    args = demisto.args()
    tags = args.get('tags', tags)
    security_labels = args.get('securityLabel', security_labels)
    description = args.get('description', description)
    status = args.get('status', status)
    group_type = args.get('group_type', group_type)
    event_date = args.get('eventDate', event_date)
    first_seen = args.get('firstSeen', first_seen)
    name = args.get('name', name)
    if tags:
        tmp = []
        for tag in tags.split(','):  # type: ignore
            tmp.append({'name': tag})
        tags = tmp  # type: ignore
    if security_labels:
        security_labels = [{'name': security_labels}]  # type: ignore

    payload = {
        "type": group_type,
        "name": name,
        "status": status,
        "tags": {
            "data": tags
        },
        "securityLabels": {
            "data": security_labels
        },
        "body": description
    }
    if event_date:
        payload['eventDate'] = event_date
    if first_seen:
        payload['firstSeen'] = first_seen
    if group_type == 'Document':
        del payload['status']
        file_name = args.get('file_name')
        malware = args.get('malware', 'false')
        payload['fileName'] = file_name
        if malware == 'true':
            password = args.get('password', '')
            payload['malware'] = malware
            payload['password'] = password
    url = '/api/v3/groups'
    response, status_code = client.make_request(Method.POST, url, payload=json.dumps(payload))  # type: ignore
    if status_code != 201:
        return_error('Error from the API: ' + response.get('message',
                                                           'An error has occurred if it persist please contact your '
                                                           'local help desk'))
    return response, status_code


def tc_add_indicator_command(client: Client, rating: str = '0', indicator: str = '', confidence: str = '0',
                             description: str = '', tags: list = [],
                             indicator_type: str = '') -> Any:  # pragma: no cover # noqa
    args = demisto.args()
    tags = args.get('tags', tags)
    description = args.get('description', description)
    confidence = args.get('confidence', confidence)
    rating = args.get('rating', rating)
    indicator = args.get('indicator', indicator)
    indicator_type = args.get('indicatorType', indicator_type)
    if tags:
        tmp = []
        for tag in tags.split(','):  # type: ignore
            tmp.append({'name': tag})
        tags = tmp  # type: ignore

    payload = {
        "type": indicator_type,
        "confidence": confidence,
        "rating": rating,
        "tags": {
            "data": tags
        },
        "summary": indicator,
        "body": description
    }
    if indicator_type == 'Host':
        payload['hostName'] = indicator
    if indicator_type == 'Address':
        payload['ip'] = indicator
    if indicator_type == 'URL':
        payload['text'] = indicator
    if indicator_type == 'EmailAddress':
        payload['address'] = indicator
    if indicator_type == 'File':
        hash_type = args.get('hashType', 'md5')
        payload[hash_type] = indicator

    url = '/api/v3/indicators'
    response, status_code = client.make_request(Method.POST, url, payload=json.dumps(payload))  # type: ignore
    if status_code != 201:
        return_error('Error from the API: ' + response.get('message',
                                                           'An error has occurred if it persist please contact your '
                                                           'local help desk'))
    ec, indicators = create_context([response.get('data')])
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': response,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Created new indicator successfully:', indicators,
                                         headerTransform=pascalToSpace),
        'EntryContext': ec
    })


def tc_update_indicator_command(client: Client, rating: str = None, indicator: str = None, confidence: str = None,
                                dns_active: str = None, tags: str = None,
                                security_labels: str = None, return_raw: bool = False, whois_active: str = None,
                                mode: str = 'append', incident_id: str = None) -> Any:  # pragma: no cover
    args = demisto.args()
    payload = {}
    indicator = args.get('indicator', indicator)
    if args.get('tags', tags):
        tmp = []
        for tag in args.get('tags', tags).split(','):
            tmp.append({'name': tag})
        payload['tags'] = {'data': tmp, 'mode': mode}
    if args.get('securityLabel', security_labels):
        security_labels = [{'name': args.get('securityLabel', security_labels)}]  # type: ignore
        payload['securityLabels'] = {'data': security_labels, 'mode': 'replace'}  # type: ignore
    if args.get('confidence', confidence):
        payload['confidence'] = args.get('confidence', confidence)
    if args.get('rating', rating):
        payload['rating'] = args.get('rating', rating)
    if args.get('dnsActive', dns_active):
        payload['dnsActive'] = args.get('dnsActive', dns_active)
    if args.get('whoisActive', whois_active):
        payload['whoisActive'] = args.get('whoisActive', whois_active)
    if args.get('incidentId', incident_id):
        payload['associatedGroups'] = {'data': [{'id': args.get('incidentId', incident_id)}], 'mode': mode}

    url = f'/api/v3/indicators/{indicator}'
    response, status_code = client.make_request(Method.PUT, url, payload=json.dumps(payload))  # type: ignore
    if status_code != 200:
        return_error('Error from the API: ' + response.get('message',
                                                           'An error has occurred if it persist please contact your '
                                                           'local help desk'))
    if return_raw:
        return response, status_code
    ec, indicators = create_context([response.get('data')])

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': response,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Updated indicator successfully:', indicators,
                                         headerTransform=pascalToSpace),
        'EntryContext': ec
    })


def tc_tag_indicator_command(client: Client) -> None:  # pragma: no cover
    response, status_code = tc_update_indicator_command(client, mode='append', return_raw=True)
    ec, indicators = create_context([response.get('data')])

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': response,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(
            f'Added the tag {demisto.args().get("tags")} to indicator {demisto.args().get("indicator")} successfully',
            indicators,
            headerTransform=pascalToSpace),
        'EntryContext': ec
    })


def tc_delete_indicator_tag_command(client: Client) -> None:  # pragma: no cover
    response, status_code = tc_update_indicator_command(client, mode='delete', return_raw=True)
    ec, indicators = create_context([response.get('data')])

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': response,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(
            f'removed the tag {demisto.args().get("tags")} from indicator {demisto.args().get("indicator")} successfully',
            # type: ignore  # noqa
            indicators,
            headerTransform=pascalToSpace),
        'EntryContext': ec
    })


def tc_incident_associate_indicator_command(client: Client) -> None:  # pragma: no cover
    response, status_code = tc_update_indicator_command(client, mode='append', return_raw=True)
    ec, indicators = create_context([response.get('data')])

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': response,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(
            f'Associated the incident {demisto.args().get("incidentId")} to indicator {demisto.args().get("indicator")} successfully',
            # type: ignore  # noqa
            indicators,
            headerTransform=pascalToSpace),
        'EntryContext': ec
    })


def tc_update_group(client: Client, attribute_value: str = '', attribute_type: str = '', custom_field: str = '',
                    associated_indicator_id: str = None,
                    associated_group_id: str = '', security_labels: list = [], tags: list = [],
                    mode: str = 'append', raw_data=False) -> Any:  # pragma: no cover
    args = demisto.args()
    payload = {}
    if args.get('tags', tags):
        tmp = []
        for tag in args.get('tags', tags).split(','):
            tmp.append({'name': tag})
        payload['tags'] = {'data': tmp, 'mode': mode}
    if args.get('security_label', security_labels):
        security_labels = [{'name': args.get('security_label', security_labels)}]  # type: ignore
        if mode != 'appends':
            mode = 'replace'
        else:
            mode = 'append'
        payload['securityLabels'] = {'data': security_labels, 'mode': mode}
    if args.get('associated_group_id', associated_group_id):
        payload['associatedGroups'] = {'data': [{'id': args.get('associated_group_id', associated_group_id)}],
                                       'mode': mode}
    if args.get('associated_indicator_id', associated_indicator_id):
        payload['associatedIndicators'] = {
            'data': [{'id': args.get('associated_indicator_id', associated_indicator_id)}],
            'mode': mode}
    attribute_type = args.get('attribute_type', attribute_type)
    attribute_value = args.get('attribute_value', attribute_value)
    if attribute_value and attribute_type:
        payload['attributes'] = {"data": [{"type": attribute_type, "value": attribute_value}], 'mode': mode}
    if args.get('custom_field', custom_field):
        for field in args.get('custom_field', custom_field).split(','):
            custom = field.split('=')
            payload[custom[0]] = custom[1]

    url = f'/api/v3/groups/{args.get("id")}'
    response, status_code = client.make_request(Method.PUT, url, payload=json.dumps(payload))  # type: ignore
    if status_code != 200:
        return_error('Error from the API: ' + response.get('message',
                                                           'An error has occurred if it persist please contact your '
                                                           'local help desk'))
    if raw_data:
        return response, status_code
    ec = {
        'ID': response.get('data', {}).get('id'),
        'Name': response.get('data', {}).get('name'),
        'Owner': response.get('data', {}).get('ownerName'),
        'DateAdded': response.get('data', {}).get('dateAdded'),
        'Tag': demisto.args().get('tags'),
        'SecurityLabel': demisto.args().get('securityLabel'),
    }
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': response,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': f'Group {response.get("data").get("id")} was Successfully updated',
        'EntryContext': {
            'TC.Group(val.ID && val.ID === obj.ID)': createContext([ec], removeNull=True)
        }
    })


def tc_download_report(client: Client):  # pragma: no cover
    args = demisto.args()
    group_id = args.get('group_id')
    url = f'/api/v3/groups/{group_id}/pdf'
    response = client.make_request(Method.GET, url, parse_json=False)
    file_entry = fileResult(filename=f'report_{group_id}.pdf', data=response.content, file_type=9)
    demisto.results(file_entry)


def download_document(client: Client):  # pragma: no cover
    document_id = int(demisto.args().get('document_id'))
    url = f'/api/v3/groups/{document_id}/download'
    response = client.make_request(Method.GET, url, parse_json=False)

    file_entry = fileResult(filename=f'document_{document_id}.txt', data=response.content)
    demisto.results(file_entry)


def add_group_attribute(client: Client):  # pragma: no cover
    response, status_code = tc_update_group(client, raw_data=True)
    headers = ['Type', 'Value', 'ID', 'DateAdded', 'LastModified']
    contents = {}
    for attribute in response.get('data').get('attributes', {}).get('data', []):
        if attribute.get('type') == demisto.args().get('attribute_type'):
            contents = {
                'Type': attribute.get('type'),
                'Value': attribute.get('value'),
                'ID': attribute.get('id'),
                'DateAdded': attribute.get('dateAdded'),
                'LastModified': attribute.get('lastModified')
            }
            break
    context = {
        'TC.Group(val.ID && val.ID === obj.ID)': contents
    }

    return_outputs(
        tableToMarkdown('The attribute was added successfully to group {}'.format(demisto.args().get('id')), contents,
                        headers,
                        removeNull=True),
        context,
        attribute
    )


def add_group_security_label(client: Client):  # pragma: no cover
    tc_update_group(client, raw_data=True, mode='appends')
    args = demisto.args()
    demisto.results(
        f'The security label {args.get("security_label")} was added successfully to the group {args.get("id")}')


def associate_group_to_group(client: Client):  # pragma: no cover
    updated_group = tc_update_group(client, raw_data=True)
    args = demisto.args()
    context_entries = {
        'GroupID': args.get('id'),
        'AssociatedGroupID': args.get('associated_group_id'),
    }
    context = {
        'TC.Group.AssociatedGroup(val.GroupID && val.GroupID === obj.GroupID)': context_entries
    }
    return_outputs('The group {} was associated successfully.'.format(args.get('associated_group_id')),
                   context,
                   updated_group[0].get('data'))


def associate_indicator_to_group(client: Client):  # pragma: no cover
    updated_group = tc_update_group(client, raw_data=True)
    args = demisto.args()
    context_entries = {
        'GroupID': args.get('id'),
        'AssociatedGroupID': args.get('associated_indicator_id'),
    }
    context = {
        'TC.Indicator(val.Indicator && val.Indicator === obj.Indicator)': context_entries
    }
    return_outputs('The indicator {} was associated successfully.'.format(args.get('associated_indicator_id')),
                   context,
                   updated_group[0].get('data'))


def get_group(client: Client) -> None:  # pragma: no cover
    response, status_code = list_groups(client, return_raw=True)
    if status_code != 200:
        return_error('Error from the API: ' + response.get('message',
                                                           'An error has occurred if it persist please contact your '
                                                           'local help desk'))
    group = response.get('data')[0]

    contents = {
        'ID': group.get('id'),
        'Name': group.get('name'),
        'Owner': group.get('ownerName'),
        'DateAdded': group.get('dateAdded'),
        'EventDate': group.get('eventDate'),
        'Status': group.get('status')
    }

    context = {
        'TC.Group(val.ID && val.ID === obj.ID)': contents
    }

    return_outputs(
        tableToMarkdown('ThreatConnect Group information', contents, removeNull=True),
        context,
        response
    )


def get_groups(client: Client) -> None:  # pragma: no cover
    response, status_code = list_groups(client, return_raw=True)
    if status_code != 200:
        return_error('Error from the API: ' + response.get('message',
                                                           'An error has occurred if it persist please contact your '
                                                           'local help desk'))
    groups = response.get('data')
    contents = []
    for group in groups:
        content = {
            'ID': group.get('id'),
            'Name': group.get('name'),
            'Owner': group.get('ownerName'),
            'DateAdded': group.get('dateAdded'),
            'EventDate': group.get('eventDate'),
            'Status': group.get('status')
        }
        contents.append(content)

    headers = ['ID', 'Name', 'OwnerName', 'EventDate', 'DateAdded', 'Status']
    context = {
        'TC.Group(val.ID && val.ID === obj.ID)': content
    }

    return_outputs(
        tableToMarkdown('ThreatConnect groups', content, headers, removeNull=True),
        context,
        response
    )


def get_group_tags(client: Client) -> None:  # pragma: no cover
    response, status_code = list_groups(client, return_raw=True, include_tags='true')
    if status_code != 200:
        return_error('Error from the API: ' + response.get('message',
                                                           'An error has occurred if it persist please contact your '
                                                           'local help desk'))
    tags = response.get('data')[0].get('tags', {}).get('data', [])
    contents = []
    context_entries = []
    for tag in tags:
        contents.append({
            'Name': tag.get('name')
        })

        context_entries.append({
            'GroupID': demisto.args().get('id'),
            'Name': tag.get('name')
        })

    context = {
        'TC.Group.Tag(val.GroupID && val.GroupID === obj.GroupID && val.Name && val.Name === obj.Name)': context_entries
    }

    return_outputs(
        tableToMarkdown('ThreatConnect Group Tags', contents, removeNull=True),
        context,
        response
    )


def get_group_indicators(client: Client) -> None:  # pragma: no cover
    response, status_code = list_groups(client, return_raw=True, include_associated_indicators='true')
    if status_code != 200:
        return_error('Error from the API: ' + response.get('message',
                                                           'An error has occurred if it persist please contact your '
                                                           'local help desk'))
    indicators = response.get('data')[0].get('associatedIndicators', {}).get('data', [])
    contents = []
    for indicator in indicators:
        contents.append({
            'GroupID': demisto.args().get('id'),
            'IndicatorID': indicator.get('id'),
            'OwnerName': indicator.get('ownerName'),
            'Type': indicator.get('type'),
            'DateAdded': indicator.get('dateAdded'),
            'LastModified': indicator.get('lastModified'),
            'Rating': indicator.get('rating'),
            'Confidence': indicator.get('confidence'),
            'ThreatAssertRating': indicator.get('threatAssessRating'),
            'ThreatAssessConfidence': indicator.get('threatAssessConfidence'),
            'Summary': indicator.get('summary')
        })

    context = {
        'TC.Group.Indicator(val.GroupID && val.GroupID === obj.GroupID && val.IndicatorID && val.IndicatorID === '
        'obj.IndicatorID)': contents
    }

    return_outputs(
        tableToMarkdown('ThreatConnect Group Indicators', contents, removeNull=True),
        context,
        response
    )


def get_group_attributes(client: Client) -> None:  # pragma: no cover
    response, status_code = list_groups(client, return_raw=True, include_attributes='true')
    if status_code != 200:
        return_error('Error from the API: ' + response.get('message',
                                                           'An error has occurred if it persist please contact your '
                                                           'local help desk'))
    attributes = response.get('data')[0].get('attributes', {}).get('data', [])
    contents = []
    headers = ['AttributeID', 'Type', 'Value', 'DateAdded', 'LastModified', 'Displayed']
    for attribute in attributes:
        contents.append({
            'GroupID': demisto.args().get('id'),
            'AttributeID': attribute.get('id'),
            'Type': attribute.get('type'),
            'Value': attribute.get('value'),
            'DateAdded': attribute.get('dateAdded'),
            'LastModified': attribute.get('lastModified'),
            'Displayed': attribute.get('displayed')
        })

    context = {
        'TC.Group.Attribute(val.GroupID && val.GroupID === obj.GroupID && val.AttributeID && val.AttributeID ==='
        ' obj.AttributeID)': contents
    }

    return_outputs(
        tableToMarkdown('ThreatConnect Group Attributes', contents, headers, removeNull=True),
        context,
        response
    )


def get_group_security_labels(client: Client) -> None:  # pragma: no cover
    response, status_code = list_groups(client, return_raw=True, include_security_labels='true')
    if status_code != 200:
        return_error('Error from the API: ' + response.get('message',
                                                           'An error has occurred if it persist please contact your '
                                                           'local help desk'))
    security_labels = response.get('data')[0].get('securityLabels', {}).get('data', [])
    contents = []
    headers = ['Name', 'Description', 'DateAdded']
    for security_label in security_labels:
        contents.append({
            'GroupID': demisto.args().get('id'),
            'Name': security_label.get('name'),
            'Description': security_label.get('description'),
            'DateAdded': security_label.get('dateAdded')
        })

    context = {
        'TC.Group.SecurityLabel(val.GroupID && val.GroupID === obj.GroupID && val.Name && val.Name === '
        'obj.Name)': contents
    }

    return_outputs(
        tableToMarkdown('ThreatConnect Group Security Labels', contents, headers, removeNull=True),
        context
    )


def add_group_tag(client: Client):  # pragma: no cover
    tags: str = demisto.args().get('tag_name')
    tc_update_group(client, raw_data=True, tags=tags)  # type: ignore
    args = demisto.args()
    demisto.results(f'The tag {tags.split(",")} was added successfully to group {args.get("group_id")}')


COMMANDS = {
    'test-module': test_integration,
    'ip': get_ip_indicators,
    'url': get_url_indicators,
    'file': get_file_indicators,
    'domain': get_domain_indicators,
    'tc-add-group-attribute': add_group_attribute,
    'tc-add-group-security-label': add_group_security_label,
    'tc-add-group-tag': add_group_tag,
    'tc-associate-group-to-group': associate_group_to_group,
    'tc-group-associate-indicator': associate_indicator_to_group,
    'tc-get-group': get_group,
    'tc-get-groups': get_groups,
    'tc-get-group-tags': get_group_tags,
    'tc-get-group-indicators': get_group_indicators,
    'tc-get-group-attributes': get_group_attributes,
    'tc-get-group-security-labels': get_group_security_labels,
    'tc-list-groups': list_groups,
    'tc-owners': tc_get_owners_command,
    'tc-indicators': tc_get_indicators_command,
    'tc-get-tags': tc_get_tags_command,
    'tc-tag-indicator': tc_tag_indicator_command,
    'tc-get-indicators-by-tag': tc_get_indicators_by_tag_command,
    'tc-add-indicator': tc_add_indicator_command,
    'tc-update-group': tc_update_group,
    'tc-create-incident': tc_create_incident_command,
    'tc-fetch-incidents': tc_fetch_incidents_command,
    'tc-get-incident-associate-indicators': tc_get_incident_associate_indicators_command,
    'tc-incident-associate-indicator': tc_incident_associate_indicator_command,
    'tc-update-indicator': tc_update_indicator_command,
    'tc-delete-indicator': tc_delete_indicator_command,
    'tc-delete-indicator-tag': tc_delete_indicator_tag_command,
    'tc-create-campaign': tc_create_campaign_command,
    'tc-create-event': tc_create_event_command,
    'tc-get-events': tc_get_events,
    'tc-get-indicator': tc_get_indicator_command,
    'tc-create-threat': tc_create_threat_command,
    'tc-delete-group': tc_delete_group_command,
    'tc-get-indicator-types': tc_get_indicator_types,
    'tc-create-document-group': create_document_group,
    'tc-download-document': download_document,
    'tc-get-associated-groups': get_group_associated_groups,
    'tc-get-indicator-owners': tc_get_indicator_owners,
    'tc-download-report': tc_download_report,
}


def main(params):  # pragma: no cover
    try:
        insecure = not params.get('insecure')
        client = Client(params.get('accessId'), params.get('api_secret_key').get('password'), params.get('baseUrl'),
                        insecure)
        command = demisto.command()
        if command in COMMANDS.keys():
            COMMANDS[command](client)  # type: ignore

    except Exception as e:
        return_error(f'An error has occurred: {str(e)}', error=e)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main(demisto.params())
