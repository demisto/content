import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import copy
import hashlib
import hmac
from enum import Enum
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


class Client(BaseClient):
    def __init__(self, api_id: str, api_secret: str, base_url: str, verify: bool = True, proxy: bool = False):
        super().__init__(base_url=base_url, proxy=proxy, verify=verify)
        self.api_id = api_id
        self.api_secret = api_secret
        self.base_url = base_url
        self.verify = verify

    def make_request(self, method: Method, url_suffix: str, payload: dict = None, params: dict = None,
                     parse_json=True, content_type=None, responseType='json'):  # pragma: no cover # noqa # type: ignore
        headers = self.create_header(url_suffix, method)
        if content_type:
            headers['Content-Type'] = content_type
        response = self._http_request(method=method, url_suffix=url_suffix, data=payload, resp_type=responseType,
                                      params=params,
                                      headers=headers)
        return response

    def create_header(self, url_suffix: str, method: Method) -> dict:
        timestamp = round(time.time())
        to_sign = f'{url_suffix}:{method}:{timestamp}'
        hash = base64.b64encode(
            hmac.new(self.api_secret.encode('utf8'), to_sign.encode('utf8'), hashlib.sha256).digest()).decode()
        return {'Authorization': f'TC {self.api_id}:{hash}', 'Timestamp': str(timestamp),
                'Content-Type': 'application/json'}


def create_context(indicators, include_dbot_score=False, fields_to_return: list = None):
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
    human_readable = []
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

        new_indicator = {
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
        }
        # relevant for domain
        if indicator_type == 'domain':
            new_indicator['Active'] = ind.get('whoisActive')

        # relevant for file
        elif indicator_type == 'file':
            new_indicator['File.MD5'] = md5
            new_indicator['File.SHA1'] = sha1
            new_indicator['File.SHA256'] = sha256

        human_readable.append(new_indicator)

        # The context should not contain the additional fields (there are added a separate HR message after)
        context_indicator = copy.deepcopy(new_indicator)
        if fields_to_return:
            for field in fields_to_return:
                context_indicator[field.capitalize()] = ind.get(field)

        context[TC_INDICATOR_PATH].append(context_indicator)

    context['DBotScore'] = list(indicators_dbot_score.values())
    context = {k: createContext(v)[:MAX_CONTEXT] for k, v in context.items() if v}
    return context, human_readable


def detection_to_incident(threatconnect_data: dict, threatconnect_date: str) -> dict:
    threatconnect_id: str = threatconnect_data.get('id', '')
    threatconnect_type: str = threatconnect_data.get('riskEventType', '')
    threatconnect_detail: str = threatconnect_data.get('riskDetail', '')
    incident = {
        'name': f'Threatconnect:'
                f' {threatconnect_id} {threatconnect_type} {threatconnect_detail}',
        'occurred': f'{threatconnect_date}',
        'rawJSON': json.dumps(threatconnect_data)
    }
    return incident


def get_indicator_reputation(client: Client, args_type: str, type_name: str, args: dict) -> None:  # pragma: no cover
    owners_query = create_or_query(args.get('owners', demisto.params().get('defaultOrg')), 'ownerName')
    query = create_or_query(args.get(args_type), 'summary')  # type: ignore
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

    response = client.make_request(Method.GET, url)

    indicators = response.get('data')

    ec, human_readable = create_context(indicators, include_dbot_score=True)
    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': indicators,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(f'ThreatConnect URL Reputation for: {args.get(args_type)}',
                                         human_readable,
                                         headerTransform=pascalToSpace, removeNull=True),
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


def get_ip_indicators(client: Client, args: dict):  # pragma: no cover
    return get_indicator_reputation(client, 'ip', 'Address', args)


def get_url_indicators(client: Client, args: dict):  # pragma: no cover
    return get_indicator_reputation(client, 'url', 'URL', args)


def get_domain_indicators(client: Client, args: dict):  # pragma: no cover
    return get_indicator_reputation(client, 'domain', 'Host', args)


def get_file_indicators(client: Client, args: dict):
    return get_indicator_reputation(client, 'file', 'File', args)


def tc_delete_group_command(client: Client, args: dict) -> Any:  # pragma: no cover
    group_ids = args.get('groupID').split(',')  # type: ignore
    success = []
    fail = []
    for id in group_ids:
        url = f'/api/v3/groups/{id}'
        response = client.make_request(Method.DELETE, url)
        if response.get('status') == 'Success':
            success.append(id)
        else:
            fail.append(id)
    success_text = ''
    fail_text = ''
    if success:
        success_text = f'{", ".join(success)} was deleted successfully.'
    if fail:
        fail_text = f'{", ".join(fail)} could not be deleted.'
    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': f'{success_text} {fail_text}'
    })


def tc_get_indicators(client: Client, tag: str = '', page: str = '0', limit: str = '500', owners: str = '',
                      indicator_id: str = '', summary: str = '',
                      fields_to_return: list = None) -> Any:  # pragma: no cover
    tql_prefix = ''
    if summary:
        summary = f' AND summary EQ "{summary}"'
        tql_prefix = '?tql='

    if tag:
        tag = f' AND tag LIKE "%{tag}%"'
        tql_prefix = '?tql='

    if owners:
        owners = ' AND ' + create_or_query(owners, 'ownerName')
        tql_prefix = '?tql='
    if indicator_id:
        indicator_id = ' AND ' + create_or_query(indicator_id, 'id').replace('"', '')
        tql_prefix = '?tql='
    fields = set_fields(fields_to_return)

    tql = f'{indicator_id}{summary}{owners}{tag}'.replace(' AND ', '', 1)
    tql = urllib.parse.quote(tql.encode('utf8'))
    url = f'/api/v3/indicators{tql_prefix}{tql}{fields}&resultStart={page}&resultLimit={limit}'
    if not tql_prefix:
        url = url.replace('&', '?', 1)
    response = client.make_request(Method.GET, url)

    return response.get('data')


def tc_get_owners_command(client: Client, args: dict) -> Any:  # pragma: no cover # type: ignore # noqa
    url = '/api/v3/security/owners'

    response = client.make_request(Method.GET, url)

    owners = []
    for owner in response.get('data'):
        owners.append({
            'ID': owner['id'],
            'Type': owner['type'],
            'Name': owner['name']
        })

    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': response.get('data'),
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('ThreatConnect Owners:', owners),
        'EntryContext': {'TC.Owner(val.ID && val.ID === obj.ID)': owners}
    })


def tc_get_indicators_command(client: Client, args: dict):
    owners = args.get('owner', '')
    limit = args.get('limit', '500')
    page = args.get('page', '0')
    fields_to_return = argToList(args.get('fields_to_return') or [])
    indicators = tc_get_indicators(client=client, owners=owners, limit=limit, page=page)
    ec, human_readable = create_context(indicators, include_dbot_score=True, fields_to_return=fields_to_return)
    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': indicators,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('ThreatConnect Indicators:', human_readable, headerTransform=pascalToSpace,
                                         removeNull=True),
        'EntryContext': ec
    })


def tc_get_indicator_owners(client: Client, args: dict) -> Any:  # pragma: no cover
    indicator = args.get('indicator')
    url = f'/api/v3/indicators/{indicator}'
    owners_raw = client.make_request(Method.GET, url)
    owner = owners_raw.get('data').get('ownerName')
    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': owners_raw.get('data'),
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': f'ThreatConnect Owner for Indicator: {indicator} is {owner}',
        'EntryContext': {'TC.Owners': owner}
    })
    return_results(f'ThreatConnect Owner for Indicator: {indicator} is {owner}')


def get_group_associated_groups(client: Client, args: dict) -> Any:  # pragma: no cover
    group_id = args.get('group_id')
    response = list_groups(client, args, include_associated_groups='true', return_raw=True,
                           group_id=group_id)  # type: ignore
    headers = ['GroupID', 'Name', 'Type', 'OwnerName', 'DateAdded']

    data = response
    contents = []
    # We get the group by a unique id, so we'll always get one result
    for group in data[0].get('associatedGroups').get('data', []):
        contents.append({
            'GroupID': group.get('id'),
            'Name': group.get('name'),
            'Type': group.get('type'),
            'DateAdded': group.get('dateAdded'),
            'OwnerName': group.get('ownerName')
        })

    context = {
        'TC.Group.AssociatedGroup(val.GroupID && val.GroupID === obj.GroupID)': contents
    }

    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': response,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('ThreatConnect Associated Groups', contents, headers, removeNull=True),
        'EntryContext': context
    })


def integration_test(client: Client, args: dict) -> None:  # pragma: no cover
    url = '/api/v3/groups?resultLimit=1'
    client.make_request(Method.GET, url)
    return_results('ok')


def get_last_run_time(groups: list, last_run: str) -> str:
    latest_date = dateparser.parse(last_run)
    if not latest_date:
        raise DemistoException(f'There was a problem parsing {last_run=} with dateparser.parse')

    for group in groups:
        try:
            group_date = datetime.strptime(group.get('dateAdded'), '%Y-%m-%dT%H:%M:%SZ')
        except Exception as e:
            demisto.debug(f'Error parsing group date, value {group.get("dateAdded")=} error message {e}')
            raise e

        if group_date and group_date > latest_date:
            latest_date = group_date

    return latest_date.isoformat()


def convert_to_dict(arr: list):
    new_dict = {item: True for item in arr}
    return new_dict


def fetch_incidents(client: Client, *args) -> str:
    params = demisto.params()
    tags = params.get('tags', '')
    if tags == 'None':
        tags = ''
    status = params.get('status', '')
    fields = set_fields(argToList(params.get('fields')))
    max_fetch = params.get('max_fetch', '200')
    group_type = params.get('group_type', ['Incident'])
    last_run = demisto.getLastRun()
    last_run = last_run.get('last')
    demisto.debug(f'[ThreatConnect] last run: {last_run}')
    if not last_run:
        last_run = f"{params.get('first_fetch') or '3 days'} ago"
        last_run = dateparser.parse(last_run)

    last_run = str(last_run)
    response = list_groups(client, {}, group_type=group_type, fields=fields, return_raw=True, tag=tags,
                           status=status, from_date=last_run, limit=max_fetch, sort='&sorting=dateAdded%20ASC')
    incidents: list = []
    incidents.extend(
        detection_to_incident(incident, incident.get('dateAdded'))
        for incident in response
    )
    demisto.incidents(incidents)
    set_last = get_last_run_time(response, last_run)
    demisto.debug(f'Setting last run to: {set_last}')
    demisto.setLastRun({'last': set_last})
    return set_last


def tc_fetch_incidents_command(client: Client, args: dict) -> None:  # pragma: no cover
    '''
    Command deprecated in v3 integration, replaced by list_groups
    '''
    id = args.get('incidentId', '')
    response = list_groups(client, args, group_type='Incident', include_tags='true', include_attributes='true',
                           return_raw=True, group_id=id)

    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': response,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Incidents:', response, headerTransform=pascalToSpace),
        'EntryContext': {
            'TC.Incident(val.ID && val.ID === obj.ID)': createContext(response, removeNull=True),
            'ThreatConnect.incidents': response  # backward compatible
        }
    })


def tc_get_incident_associate_indicators_command(client: Client, args: dict) -> None:  # pragma: no cover
    incident_id = args.get('incidentId', '')
    response = list_groups(client, args, group_type='Incident', include_associated_indicators='true',
                           return_raw=True, group_id=incident_id)

    if not response:
        return_error('No incident groups were found for the given arguments')
    ec, human_readable = create_context(response[0].get('associatedIndicators', {}).get('data', []),
                                        include_dbot_score=True)
    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': response,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Incident Associated Indicators:', human_readable,
                                         headerTransform=pascalToSpace, removeNull=True),
        'EntryContext': ec
    })


def tc_get_events(client: Client, args: dict) -> None:  # pragma: no cover
    response = list_groups(client, args, group_type='Event', return_raw=True)

    content = []
    headers = ['ID', 'Name', 'OwnerName', 'EventDate', 'DateAdded', 'Status', 'Tags', 'AssociatedIndicators',
               'AssociatedGroups']

    for event in response:
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

    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': json.dumps(response),
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('ThreatConnect Events', content, headers, removeNull=True),
        'EntryContext': context
    })


def tc_create_event_command(client: Client, args: dict) -> None:  # pragma: no cover
    tags = args.get('tag')
    status = args.get('status', 'Needs Review')
    owner_name = args.get('owner_name', '')
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
        "ownerName": owner_name if owner_name else None,
        "tags": {
            "data": tags_list
        }
    })
    url = '/api/v3/groups'
    response = client.make_request(Method.POST, url, payload=payload)  # type: ignore

    ec = {
        'ID': response.get('data').get('id'),
        'Name': response.get('data').get('name'),
        'Owner': response.get('data').get('ownerName'),
        'Date': response.get('data').get('eventDate'),
        'Tags': response.get('data').get('tags'),
        'Status': response.get('data').get('status'),
        'Type': response.get('data').get('type'),
    }
    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': json.dumps(response.get('data')),
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': f'Incident {name} with ID {ec.get("ID")} Created Successfully',
        'EntryContext': {
            'TC.Event(val.ID && val.ID === obj.ID)': createContext([ec], removeNull=True)
        }
    })


def set_fields(fields: Optional[list]) -> str:  # pragma: no cover
    fields_str = ''
    if fields:
        if 'include_all_metadata' in fields:
            return '&fields=tags&fields=associatedIndicators&fields=associatedGroups&fields=securityLabels' \
                   '&fields=attributes&fields=associatedVictimAssets'
        for field in fields:
            fields_str += f'&fields={field}'
    return fields_str


def list_groups(client: Client, args: dict, group_id: str = '', from_date: str = '', tag: str = '',
                security_label: str = '',
                group_type: str = '', tql_filter: str = '', include_security_labels: str = '',
                include_attributes: str = '',
                include_tags: str = '', include_associated_groups: str = '', include_associated_indicators: str = '',
                include_all_metadata: str = '', status: str = '', owner: str = '', limit: str = '100', fields: str = '',
                return_raw=False, sort='') -> Any:
    # TQL PARAMS
    group_id = args.get('id', group_id)
    from_date = args.get('fromDate', from_date)
    tag = args.get('tag', tag)
    security_label = args.get('security_label', security_label)
    group_type = args.get('group_type', group_type)
    tql_filter = args.get('filter', tql_filter)
    # PAGINATION PARAMS
    limit = args.get('limit', limit)
    page = args.get('page', '0')

    tql_prefix = ''
    tql = ''
    if from_date:
        from_date = f' AND dateAdded > "{from_date}" '
        tql_prefix = '?tql='
    if group_type:
        if type(group_type) == list:
            group_type = f' AND ({create_or_query(", ".join(group_type), "typeName")})'
        else:
            group_type = f' AND typeName EQ "{group_type}"'
        tql_prefix = '?tql='
    if owner:
        group_type = f' AND ownerName EQ "{owner}"'
        tql_prefix = '?tql='
    if status:
        group_type = f' AND status EQ "{status}"'
        tql_prefix = '?tql='
    if security_label:
        security_label = f' AND securityLabel like "%{security_label}%"'
        tql_prefix = '?tql='
        include_security_labels = 'True'
    if tag:
        tags = tag.split(',')
        for tag_to_find in tags:
            tag += f' AND tag like "%{tag_to_find}%"'
        tql_prefix = '?tql='
        include_tags = 'true'
    if tql_filter:
        tql_filter = f' AND {tql_filter}'
        tql_prefix = '?tql='
    if group_id:
        group_id = f' AND ({create_or_query(group_id, "id", "")})'
        tql_prefix = '?tql='
    if not fields:
        # FIELDS PARAMS
        include_all_metadata = args.get('include_all_metadata', include_all_metadata)
        include_associated_indicators = args.get('include_associated_indicators', include_associated_indicators)
        include_associated_groups = args.get('include_associated_groups', include_associated_groups)
        include_attributes = args.get('include_attributes', include_attributes)
        include_security_labels = args.get('include_security_labels', include_security_labels)
        include_tags = args.get('include_tags', include_tags)

        # we create a list of fields to return based on the given arguments
        list_of_fields = [field for field, should_include in
                          {'tags': include_tags, 'securityLabels': include_security_labels,
                           'attributes': include_attributes,
                           'associatedGroups': include_associated_groups,
                           'associatedIndicators': include_associated_indicators,
                           'include_all_metadata': include_all_metadata}.items() if
                          (should_include and should_include != 'false')]
        fields = set_fields(list_of_fields)
    if tql_prefix:
        tql = f'{tql_filter}{group_id}{group_type}{from_date}{tag}{security_label}'.replace(' AND ', '', 1)
        tql = urllib.parse.quote(tql.encode('utf8'))
        tql = f'?tql={tql}'
    url = f'/api/v3/groups{tql}{fields}&resultStart={page}&resultLimit={limit}{sort}'
    if not tql_prefix:
        url = url.replace('&', '?', 1)
    demisto.debug(url)
    response = client.make_request(Method.GET, url)

    if return_raw:
        return response.get('data')
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

    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': content,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('ThreatConnect Groups', content, headers, removeNull=True),
        'EntryContext': context
    })
    return None


def tc_get_tags_command(client: Client, args: dict) -> None:  # pragma: no cover
    limit = args.get('limit', '500')
    page = args.get('page', '0')
    name = args.get('name', '')

    if name:
        name = 'tql=' + urllib.parse.quote(f'summary EQ "{name}" &'.encode())

    url = f'/api/v3/tags?{name}resultStart={page}&resultLimit={limit}'
    response = client.make_request(Method.GET, url)

    tags = [t['name'] for t in response.get('data')]

    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': json.dumps(response.get('data')),
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('ThreatConnect Tags:', tags, headers='Name'),
        'EntryContext': {'TC.Tags': tags}
    })


def tc_get_indicator_types(client: Client, args: dict) -> None:  # pragma: no cover
    url = '/api/v2/types/indicatorTypes'
    content = []
    response = client.make_request(Method.GET, url)

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

    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': content,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('ThreatConnect indicator types', content, headers, removeNull=True),
        'EntryContext': context
    })


def tc_get_indicators_by_tag_command(client: Client, args: dict) -> None:  # pragma: no cover
    owners: str = args.get('owner', '')
    limit: str = args.get('limit', '500')
    page: str = args.get('page', '0')
    tag: str = args.get('tag') or ''
    fields_to_return = argToList(args.get('fields_to_return') or []).append(['tags'])
    indicators = tc_get_indicators(client, owners=owners, limit=limit, page=page, tag=tag,
                                   fields_to_return=fields_to_return)
    ec, human_readable = create_context(indicators, include_dbot_score=True)

    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': indicators,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('ThreatConnect Indicators with tag: {}'.format(args.get('tag')),
                                         human_readable,
                                         headerTransform=pascalToSpace, removeNull=True),
        'EntryContext': ec
    })


def tc_get_indicator_command(client: Client, args: dict) -> None:  # pragma: no cover
    indicator = args.get('indicator', '')
    fields_to_return = argToList(args.get('fields_to_return') or [])
    indicator_id = ''
    summary = ''
    # We do this to check if the given indicator is an ID or a summary
    if indicator.isdigit():
        # If it's an int it means that it's an ID
        indicator_id = indicator
    else:
        # If not we'll treat it as a summary
        summary = indicator  # type: ignore

    response = tc_get_indicators(client, indicator_id=indicator_id, summary=summary,
                                 fields_to_return=fields_to_return)  # type: ignore
    ec, human_readable = create_context(response, include_dbot_score=True, fields_to_return=fields_to_return)
    if not ec:
        return_results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['text'],
            'Contents': f'Could not find indicator: {indicator}'
        })
    else:
        include_attributes = response[0].get('attributes')
        include_observations = response[0].get('observations')
        include_tags = response[0].get('tags')
        associated_indicators = response[0].get('associatedIndicators')
        associated_groups = response[0].get('associatedGroups')

        return_results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': response,
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown('ThreatConnect indicator for: {}'.format(args.get('indicator', '')),
                                             human_readable, headerTransform=pascalToSpace, removeNull=True),
            'EntryContext': ec
        })

        if associated_groups:
            return_results({
                'Type': entryTypes['note'],
                'ContentsFormat': formats['json'],
                'ReadableContentsFormat': formats['markdown'],
                'HumanReadable': tableToMarkdown(
                    'ThreatConnect Associated Groups for indicator: {}'.format(args.get('indicator', '')),
                    associated_groups.get('data', []),
                    headerTransform=pascalToSpace)
            })

        if associated_indicators:
            return_results({
                'Type': entryTypes['note'],
                'ContentsFormat': formats['json'],
                'ReadableContentsFormat': formats['markdown'],
                'HumanReadable': tableToMarkdown(
                    'ThreatConnect Associated Indicators for indicator: {}'.format(args.get('indicator', '')),
                    associated_indicators.get('data', []),
                    headerTransform=pascalToSpace)
            })

        if include_tags:
            return_results({
                'Type': entryTypes['note'],
                'ContentsFormat': formats['json'],
                'ReadableContentsFormat': formats['markdown'],
                'HumanReadable': tableToMarkdown(
                    'ThreatConnect Tags for indicator: {}'.format(args.get('indicator', '')),
                    include_tags.get('data', []),
                    headerTransform=pascalToSpace)
            })

        if include_attributes:
            return_results({
                'Type': entryTypes['note'],
                'ContentsFormat': formats['json'],
                'ReadableContentsFormat': formats['markdown'],
                'HumanReadable': tableToMarkdown(
                    'ThreatConnect Attributes for indicator: {}'.format(args.get('indicator', '')),
                    include_attributes.get('data', []),
                    headerTransform=pascalToSpace)
            })

        if include_observations:
            return_results({
                'Type': entryTypes['note'],
                'ContentsFormat': formats['json'],
                'ReadableContentsFormat': formats['markdown'],
                'HumanReadable': tableToMarkdown(
                    'ThreatConnect Observations for indicator: {}'.format(args.get('id', '')),
                    include_observations,
                    headerTransform=pascalToSpace)
            })


def tc_delete_indicator_command(client: Client, args: dict) -> None:  # pragma: no cover
    indicator_id = args.get('indicator')
    url = f'/api/v3/indicators/{indicator_id}'
    client.make_request(Method.DELETE, url)

    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': f'Indicator {indicator_id} removed Successfully'
    })


def create_document_group(client: Client, args: dict) -> None:  # pragma: no cover
    name = args.get('name')
    security_label = args.get('security_label')
    description = args.get('description', '')
    response = create_group(client, args, security_labels=security_label,  # type: ignore
                            name=name, group_type='Document', description=description)  # type: ignore
    res = demisto.getFilePath(args.get('entry_id'))
    f = open(res['path'], 'rb')
    contents = f.read()
    url = f'/api/v3/groups/{response.get("id")}/upload'
    payload = f"{contents}"  # type: ignore
    client.make_request(Method.POST, url, payload=payload, content_type='application/octet-stream')  # type: ignore

    content = {
        'ID': response.get('id'),
        'Name': response.get('name'),
        'Owner': response.get('ownerName', ''),
        'EventDate': response.get('eventDate', ''),
        'Description': description,
        'SecurityLabel': security_label
    }
    context = {
        'TC.Group(val.ID && val.ID === obj.ID)': content
    }

    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': response,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('ThreatConnect document group was created successfully', content,
                                         removeNull=True),
        'EntryContext': context
    })


def tc_create_threat_command(client: Client, args: dict) -> None:  # pragma: no cover
    response = create_group(client, args, group_type='Threat')

    ec = {
        'ID': response.get('id'),
        'Name': response.get('name'),
        'Owner': response.get('ownerName'),
        'FirstSeen': response.get('FirstSeen'),
        'Tag': args.get('tags'),
        'SecurityLabel': args.get('securityLabel'),
    }
    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': response,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': f'Threat {args.get("name")} Created Successfully with id: {response.get("id")}',
        # type: ignore  # noqa
        'EntryContext': {
            'TC.Threat(val.ID && val.ID === obj.ID)': createContext([ec], removeNull=True)
        }
    })


def tc_create_campaign_command(client: Client, args: dict) -> None:  # pragma: no cover
    tags = args.get('tag', [])
    response = create_group(client, args, group_type='Campaign', tags=tags)

    ec = {
        'ID': response.get('id'),
        'Name': response.get('name'),
        'Owner': response.get('ownerName'),
        'FirstSeen': response.get('FirstSeen'),
        'Tag': args.get('tags'),
        'SecurityLabel': args.get('securityLabel'),
    }
    human = f'Campaign {args.get("name")} was created Successfully with id: {response.get("id")}'
    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': response,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human,
        # type: ignore # noqa
        'EntryContext': {
            'TC.Campaign(val.ID && val.ID === obj.ID)': createContext([ec], removeNull=True)
        }
    })


def tc_create_incident_command(client: Client, args: dict) -> None:  # pragma: no cover
    name = args.get('incidentName')
    tags = args.get('tag')
    security_labels = args.get('securityLabels')
    response = create_group(client, args, group_type='Incident', tags=tags, name=name,  # type: ignore
                            security_labels=security_labels)  # type: ignore

    ec = {
        'ID': response.get('id'),
        'Name': response.get('name'),
        'Owner': response.get('ownerName'),
        'EventDate': response.get('eventDate'),
        'Tag': args.get('tags'),
        'SecurityLabel': args.get('securityLabel'),
    }
    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': response.get('data'),
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': f'Incident {name} Created Successfully with id: {response.get("id")}',
        # type: ignore  # noqa
        'EntryContext': {
            'TC.Incident(val.ID && val.ID === obj.ID)': createContext([ec], removeNull=True)
        }
    })


def create_group(client: Client, args: dict, name: str = '', event_date: str = '', group_type: str = '',
                 status: str = 'New', description: str = '', security_labels: str = '',
                 tags: list = [], first_seen: str = ''):  # pragma: no cover
    tags = args.get('tags', tags)
    security_labels = args.get('securityLabel', security_labels)
    description = args.get('description', description)
    status = args.get('status', status)
    group_type = args.get('group_type', group_type)
    event_date = args.get('eventDate', event_date)
    first_seen = args.get('firstSeen', first_seen)
    name = args.get('name', name)
    payload = {
        "type": group_type,
        "name": name,
        "status": status,
        "body": description
    }
    if tags:
        tmp = []
        for tag in tags.split(','):  # type: ignore
            tmp.append({'name': tag})
        payload['tags'] = {
            "data": tmp
        }
    if security_labels:
        payload['securityLabels'] = {
            "data": [{'name': security_labels}]
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
    response = client.make_request(Method.POST, url, payload=json.dumps(payload))  # type: ignore

    return response.get('data')


def tc_add_indicator_command(client: Client, args: dict, rating: str = '0', indicator: str = '', confidence: str = '0',
                             description: str = '', tags: list = [],
                             indicator_type: str = '') -> Any:  # pragma: no cover # noqa
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
    response = client.make_request(Method.POST, url, payload=json.dumps(payload))  # type: ignore

    ec, human_readable = create_context([response.get('data')])
    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': response.get('data'),
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Created new indicator successfully:', human_readable,
                                         headerTransform=pascalToSpace, removeNull=True),
        'EntryContext': ec
    })


def tc_update_indicator_command(client: Client, args: dict, rating: str = None, indicator: str = None,
                                confidence: str = None,
                                dns_active: str = None, tags: str = None,
                                security_labels: str = None, return_raw: bool = False, whois_active: str = None,
                                mode: str = 'append', incident_id: str = None) -> Any:  # pragma: no cover
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
    response = client.make_request(Method.PUT, url, payload=json.dumps(payload))  # type: ignore[arg-type]

    if return_raw:
        return response.get('data'),
    ec, human_readable = create_context([response.get('data')])

    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': response.get('data'),
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Updated indicator successfully:', human_readable,
                                         headerTransform=pascalToSpace, removeNull=True),
        'EntryContext': ec
    })
    return None


def tc_tag_indicator_command(client: Client, args: dict) -> None:  # pragma: no cover
    tags = args.get('tag')
    response = tc_update_indicator_command(client, args, mode='append', return_raw=True, tags=tags)
    ec, human_readable = create_context([response], fields_to_return=['tags'])

    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': response,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(
            f'Added the tag {args.get("tags")} to indicator {args.get("indicator")} successfully',
            human_readable, headerTransform=pascalToSpace, removeNull=True),
        'EntryContext': ec
    })


def tc_delete_indicator_tag_command(client: Client, args: dict) -> None:  # pragma: no cover
    tag = args.get('tag')
    indicator_id = args.get('indicator')
    response = tc_update_indicator_command(client, args, mode='delete', return_raw=True, tags=tag,
                                           indicator=indicator_id)
    ec, human_readable = create_context([response], fields_to_return=['tags'])

    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': response,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(
            f'removed the tag {tag} from indicator {indicator_id} successfully',
            # type: ignore  # noqa
            human_readable,
            headerTransform=pascalToSpace, removeNull=True),
        'EntryContext': ec
    })


def tc_incident_associate_indicator_command(client: Client, args: dict) -> None:  # pragma: no cover
    group_id = args.get('incidentId')
    indicator = args.get('indicator')
    response = tc_update_group(client, args, mode='append', raw_data=True, group_id=group_id,
                               associated_indicator_id=indicator)
    ec, human_readable = create_context([response.get('data')])

    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': response.get('data'),
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(
            f'Associated the incident {group_id} to indicator {indicator} successfully',
            human_readable,
            headerTransform=pascalToSpace, removeNull=True),
        'EntryContext': ec
    })


def tc_update_group(client: Client, args: dict, attribute_value: str = '', attribute_type: str = '',
                    custom_field: str = '',
                    associated_indicator_id: str = None,
                    associated_group_id: str = '', security_labels: list = [], tags: list = [],
                    mode: str = 'append', raw_data=False, group_id=None) -> Any:  # pragma: no cover
    payload = {}
    if args.get('tags', tags):
        tmp = []
        for tag in args.get('tags', tags).split(','):
            tmp.append({'name': tag})
        payload['tags'] = {'data': tmp, 'mode': mode}
    if args.get('security_label', security_labels):
        security_labels = [{'name': args.get('security_label', security_labels)}]  # type: ignore
        mode = 'replace' if mode != 'appends' else 'append'
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
    if not group_id:
        group_id = args.get("id")
    url = f'/api/v3/groups/{group_id}'
    response = client.make_request(Method.PUT, url, payload=json.dumps(payload))  # type: ignore

    if raw_data:
        return response.get('data')
    ec = {
        'ID': response.get('data', {}).get('id'),
        'Name': response.get('data', {}).get('name'),
        'Owner': response.get('data', {}).get('ownerName'),
        'DateAdded': response.get('data', {}).get('dateAdded'),
        'Tag': args.get('tags'),
        'SecurityLabel': args.get('securityLabel'),
    }
    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': response.get('data'),
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': f'Group {response.get("data").get("id")} was Successfully updated',
        'EntryContext': {
            'TC.Group(val.ID && val.ID === obj.ID)': createContext([ec], removeNull=True)
        }
    })
    return None


def tc_download_report(client: Client, args: dict):  # pragma: no cover
    group_id = args.get('group_id')
    url = f'/api/v3/groups/{group_id}/pdf'
    response = client.make_request(Method.GET, url, parse_json=False, responseType='response')
    file_entry = fileResult(filename=f'report_{group_id}.pdf', data=response.content, file_type=9)
    return_results(file_entry)


def download_document(client: Client, args: dict):  # pragma: no cover
    document_id = int(args.get('document_id'))  # type: ignore
    url = f'/api/v3/groups/{document_id}/download'
    response = client.make_request(Method.GET, url, parse_json=False, responseType='text')

    file_entry = fileResult(filename=f'document_{document_id}.txt', data=response)
    return_results(file_entry)


def add_group_attribute(client: Client, args: dict):  # pragma: no cover
    '''
    Command deprecated in v3 integration, replaced by tc_update_group
    '''
    group_id = args.get('group_id')
    response = tc_update_group(client, args, raw_data=True, group_id=group_id)
    headers = ['Type', 'Value', 'ID', 'DateAdded', 'LastModified']
    contents = {}
    for attribute in response.get('attributes', {}).get('data', []):
        if attribute.get('type') == args.get('attribute_type'):
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

    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(f'The attribute was added successfully to group {group_id}', contents,
                                         headers=headers),
        'EntryContext': context
    })


def add_group_security_label(client: Client, args: dict):  # pragma: no cover
    """
    Command deprecated in v3 integration, replaced by tc_update_group
    """
    group_id = args.get('group_id')
    security_label_name = args.get("security_label_name")
    tc_update_group(client, args, raw_data=True, mode='appends', group_id=group_id,
                    security_labels=security_label_name)  # type: ignore # noqa
    return_results(f'The security label {security_label_name} was added successfully to the group {group_id}')


def associate_group_to_group(client: Client, args: dict):  # pragma: no cover
    """
    Command deprecated in v3 integration, replaced by tc_update_group
    """
    group_id = args.get('group_id')
    updated_group = tc_update_group(client, args, raw_data=True, group_id=group_id)
    context_entries = {
        'GroupID': group_id,
        'AssociatedGroupID': args.get('associated_group_id'),
    }
    context = {
        'TC.Group.AssociatedGroup(val.GroupID && val.GroupID === obj.GroupID)': context_entries
    }

    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': json.dumps(updated_group),
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': 'The group {} was associated successfully.'.format(args.get('associated_group_id')),
        'EntryContext': context
    })


def associate_indicator_to_group(client: Client, args: dict):  # pragma: no cover
    """
    Command deprecated in v3 integration, replaced by tc_update_group
    """
    group_id = args.get('group_id')
    associated_indicator_id = args.get('indicator')
    updated_group = tc_update_group(client, args, raw_data=True, group_id=group_id,
                                    associated_indicator_id=associated_indicator_id)
    context_entries = {
        'GroupID': args.get('id'),
        'AssociatedGroupID': args.get('associated_indicator_id'),
    }
    context = {
        'TC.Indicator(val.Indicator && val.Indicator === obj.Indicator)': context_entries
    }

    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': json.dumps(updated_group),
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': f'The indicator {associated_indicator_id} was associated successfully.',
        'EntryContext': context
    })


def get_group(client: Client, args: dict) -> None:  # pragma: no cover
    '''
    Command deprecated in v3 integration, replaced by list_groups
    '''
    group_id = args.get('group_id')
    response = list_groups(client, args, return_raw=True, group_id=group_id)  # type: ignore

    group = response[0]

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

    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('ThreatConnect Group information', contents, removeNull=True),
        'EntryContext': context
    })


def get_groups(client: Client, args: dict) -> None:  # pragma: no cover
    '''
    Command deprecated in v3 integration, replaced by list_groups
    '''
    response = list_groups(client, args, return_raw=True)

    contents = []
    for group in response:
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
        'TC.Group(val.ID && val.ID === obj.ID)': contents
    }

    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('ThreatConnect Groups information', contents, headers=headers,
                                         removeNull=True),
        'EntryContext': context
    })


def get_group_tags(client: Client, args: dict) -> None:  # pragma: no cover
    '''
    Command deprecated in v3 integration, replaced by list_groups
    '''
    group_id = args.get('group_id')
    response = list_groups(client, args, return_raw=True, include_tags='true', group_id=group_id)  # type: ignore

    tags = response[0].get('tags', {}).get('data', [])
    contents = []
    context_entries = []
    for tag in tags:
        contents.append({
            'Name': tag.get('name')
        })

        context_entries.append({
            'GroupID': group_id,
            'Name': tag.get('name')
        })

    context = {
        'TC.Group.Tag(val.GroupID && val.GroupID === obj.GroupID && val.Name && val.Name === obj.Name)': context_entries
    }

    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('ThreatConnect Group Tags', contents, removeNull=True),
        'EntryContext': context
    })


def get_group_indicators(client: Client, args: dict) -> None:  # pragma: no cover
    '''
    Command deprecated in v3 integration, replaced by list_groups
    '''
    group_id = args.get('group_id')
    response = list_groups(client, args, return_raw=True, include_associated_indicators='true',  # type: ignore
                           group_id=group_id)  # type: ignore

    indicators = response[0].get('associatedIndicators', {}).get('data', [])
    contents = []
    for indicator in indicators:
        contents.append({
            'GroupID': group_id,
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

    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('ThreatConnect Group Indicators', contents, removeNull=True),
        'EntryContext': context
    })


def get_group_attributes(client: Client, args: dict) -> None:  # pragma: no cover
    '''
    Command deprecated in v3 integration, replaced by list_groups
    '''
    group_id = args.get('group_id')
    response = list_groups(client, args, return_raw=True, include_attributes='true', group_id=group_id)  # type: ignore

    attributes = response[0].get('attributes', {}).get('data', [])
    contents = []
    headers = ['AttributeID', 'Type', 'Value', 'DateAdded', 'LastModified', 'Displayed']
    for attribute in attributes:
        contents.append({
            'GroupID': group_id,
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

    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('ThreatConnect Group Attributes', contents, headers, removeNull=True),
        'EntryContext': context
    })


def get_group_security_labels(client: Client, args: dict) -> None:  # pragma: no cover
    '''
    Command deprecated in v3 integration, replaced by list_groups
    '''
    group_id = args.get('group_id')
    response = list_groups(client, args, return_raw=True, include_security_labels='true',
                           group_id=group_id)  # type: ignore

    security_labels = response[0].get('securityLabels', {}).get('data', [])
    contents = []
    headers = ['Name', 'Description', 'DateAdded']
    for security_label in security_labels:
        contents.append({
            'GroupID': group_id,
            'Name': security_label.get('name'),
            'Description': security_label.get('description'),
            'DateAdded': security_label.get('dateAdded')
        })

    context = {
        'TC.Group.SecurityLabel(val.GroupID && val.GroupID === obj.GroupID && val.Name && val.Name === '
        'obj.Name)': contents
    }

    return_results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('ThreatConnect Group Security Labels', contents, headers, removeNull=True),
        'EntryContext': context
    })


def add_group_tag(client: Client, args: dict):  # pragma: no cover
    group_id = args.get('group_id')
    tags: str = args.get('tag_name')  # type: ignore
    tc_update_group(client, args, raw_data=True, tags=tags, group_id=group_id)  # type: ignore
    return_results(f'The tag {tags.split(",")} was added successfully to group {group_id}')


COMMANDS = {
    'test-module': integration_test,
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
    'fetch-incidents': fetch_incidents,
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
        proxy = params.get('proxy')
        credentials = demisto.params().get('api_secret_key', {})
        access_id = credentials.get('identifier') or demisto.params().get('accessId')
        client = Client(access_id, credentials.get('password'),
                        demisto.getParam('baseUrl'), verify=insecure, proxy=proxy)
        args = demisto.args()
        command = demisto.command()
        if command in COMMANDS:
            COMMANDS[command](client, args)  # type: ignore

    except Exception as e:
        return_error(f'An error has occurred: {str(e)}', error=e)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main(demisto.params())
