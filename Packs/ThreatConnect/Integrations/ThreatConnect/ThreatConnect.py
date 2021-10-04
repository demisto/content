import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
from urlparse import urlparse
from datetime import timedelta
from distutils.util import strtobool
from threatconnect import ThreatConnect
from threatconnect.RequestObject import RequestObject
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.Config.FilterOperator import FilterOperator

'''GLOBAL VARS'''
FRESHNESS = int(demisto.params()['freshness'])
MAX_CONTEXT = 100

''' HELPER FUNCTIONS '''


def get_client():
    params = demisto.params()
    access = params['accessId']
    secret = params['secretKey']
    default_org = params.get('defaultOrg')
    url = params['baseUrl']
    proxy_ip = params['proxyIp']
    proxy_port = params['proxyPort']

    tc = ThreatConnect(access, secret, default_org, url)
    if proxy_ip and proxy_port and len(proxy_ip) > 0 and len(proxy_port) > 0:
        tc.set_proxies(proxy_ip, int(proxy_port))

    return tc


def calculate_freshness_time(freshness):
    t = datetime.now() - timedelta(days=freshness)
    return t.strftime('%Y-%m-%dT00:00:00Z')


def create_context(indicators, include_dbot_score=False):
    context = {
        'DBotScore': [],
        outputPaths['ip']: [],
        outputPaths['url']: [],
        outputPaths['domain']: [],
        outputPaths['file']: [],
        'TC.Indicator(val.ID && val.ID === obj.ID)': [],
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

        if confidence >= demisto.params()['rating'] and rating >= demisto.params()['confidence']:
            dbot_score = 3
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
                mal['MD5'] = value
                mal['SHA1'] = ind.get('sha1')
                mal['SHA256'] = ind.get('sha256')

            elif indicator_type == 'url':
                mal['Data'] = value

            elif indicator_type == 'domain':
                mal['Name'] = value

            context_path = outputPaths.get(indicator_type)
            if context_path is not None:
                context[context_path].append(mal)

        elif rating >= 1:
            dbot_score = 2
        else:
            dbot_score = 1

        if include_dbot_score:
            context['DBotScore'].append({
                'Indicator': value,
                'Score': dbot_score,
                'Type': indicator_type,
                'Vendor': 'ThreatConnect'
            })

        context['TC.Indicator(val.ID && val.ID === obj.ID)'].append({
            'ID': ind['id'],
            'Name': value,
            'Type': ind['type'],
            'Owner': ind['ownerName'],
            'Description': ind.get('description'),
            'CreateDate': ind['dateAdded'],
            'LastModified': ind['lastModified'],
            'Rating': rating,
            'Confidence': confidence,

            # relevant for domain
            'Active': ind.get('whoisActive'),

            # relevant for file
            'File.MD5': ind.get('md5'),
            'File.SHA1': ind.get('sha1'),
            'File.SHA256': ind.get('sha256'),
        })

    context = {k: createContext(v, removeNull=True)[:MAX_CONTEXT] for k, v in context.items() if len(v) > 0}
    return context, context.get('TC.Indicator(val.ID && val.ID === obj.ID)', [])


# pylint: disable=E1101
def get_indicators(indicator_value=None, indicator_type=None, owners=None, rating_threshold=-1, confidence_threshold=-1,
                   freshness=None):
    tc = get_client()
    indicators_obj = tc.indicators()
    _filter = indicators_obj.add_filter()

    if indicator_value is not None:
        _filter.add_indicator(indicator_value)
    if indicator_type is not None:
        _filter.add_pf_type(indicator_type, FilterOperator.EQ)

    if owners is not None:
        owners = owners.split(",")
        _filter.add_owner(owners)

    if rating_threshold != -1:
        _filter.add_pf_rating(rating_threshold, FilterOperator.GE)
    if confidence_threshold != -1:
        _filter.add_pf_confidence(confidence_threshold, FilterOperator.GE)
    if freshness is not None:
        _filter.add_pf_last_modified(calculate_freshness_time(freshness), FilterOperator.GE)

    raw_indicators = indicators_obj.retrieve()

    indicators = [json.loads(indicator.json) for indicator in raw_indicators]

    return indicators


''' FUNCTIONS '''


def ip_command():
    args = demisto.args()
    owners = args.get('owners', demisto.params().get('defaultOrg'))
    if not owners:
        return_error('You must specify an owner in the command, or by using the Organization parameter.')
    rating_threshold = int(args.get('ratingThreshold', -1))
    confidence_threshold = int(args.get('confidenceThreshold', -1))
    ip_addr = args['ip']

    ec, indicators = ip(ip_addr, owners, rating_threshold, confidence_threshold)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': indicators,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('ThreatConnect IP Reputation for: {}'.format(ip_addr), indicators,
                                         headerTransform=pascalToSpace),
        'EntryContext': ec
    })


@logger
def ip(ip_addr, owners, rating_threshold, confidence_threshold):
    indicators = get_indicators(ip_addr, 'Address', owners, rating_threshold, confidence_threshold)

    if not indicators:
        demisto.results('Make sure that the indicator exists in your ThreatConnect environment')
    ec, indicators = create_context(indicators, include_dbot_score=True)

    return ec, indicators


def url_command():
    args = demisto.args()
    owners = args.get('owners', demisto.params().get('defaultOrg'))
    if not owners:
        return_error('You must specify an owner in the command, or by using the Organization parameter.')
    url_addr = args['url']
    parsed_url = urlparse(url_addr)
    if not parsed_url.scheme:
        return_error('Please provide a valid URL including a protocol (http/https)')
    rating_threshold = int(args.get('ratingThreshold', -1))
    confidence_threshold = int(args.get('confidenceThreshold', -1))

    ec, indicators = url(url_addr, owners, rating_threshold, confidence_threshold)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': indicators,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('ThreatConnect URL Reputation for: {}'.format(url_addr), indicators,
                                         headerTransform=pascalToSpace),
        'EntryContext': ec
    })


@logger
def url(url_addr, owners, rating_threshold, confidence_threshold):
    indicators = get_indicators(url_addr, 'URL', owners, rating_threshold, confidence_threshold)
    if not indicators:
        demisto.results('Make sure that the indicator exists in your ThreatConnect environment')
    ec, indicators = create_context(indicators, include_dbot_score=True)

    return ec, indicators


def file_command():
    args = demisto.args()
    owners = args.get('owners', demisto.params().get('defaultOrg'))
    if not owners:
        return_error('You must specify an owner in the command, or by using the Organization parameter.')
    file_name = args['file']
    rating_threshold = int(args.get('ratingThreshold', -1))
    confidence_threshold = int(args.get('confidenceThreshold', -1))

    ec, indicators = _file(file_name, owners, rating_threshold, confidence_threshold)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': indicators,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('ThreatConnect File Report for: {}'.format(file_name), indicators,
                                         headerTransform=pascalToSpace),
        'EntryContext': ec
    })


@logger
def _file(url_addr, owners, rating_threshold, confidence_threshold):
    indicators = get_indicators(url_addr, 'File', owners, rating_threshold, confidence_threshold)
    if not indicators:
        demisto.results('Make sure that the indicator exists in your ThreatConnect environment')
    ec, indicators = create_context(indicators, include_dbot_score=True)

    return ec, indicators


def domain_command():
    args = demisto.args()
    owners = args.get('owners', demisto.params().get('defaultOrg'))
    if not owners:
        return_error('You must specify an owner in the command, or by using the Organization parameter.')
    rating_threshold = int(args.get('ratingThreshold', -1))
    confidence_threshold = int(args.get('confidenceThreshold', -1))
    domain_addr = args['domain']

    ec, indicators = domain(domain_addr, owners, rating_threshold, confidence_threshold)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': indicators,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('ThreatConnect Domain Reputation for: {}'.format(domain_addr), indicators,
                                         headerTransform=pascalToSpace),
        'EntryContext': ec
    })


@logger
def domain(domain_addr, owners, rating_threshold, confidence_threshold):
    indicators = get_indicators(domain_addr, 'Host', owners, rating_threshold, confidence_threshold)
    ec, indicators = create_context(indicators, include_dbot_score=True)

    return ec, indicators


def tc_owners_command():
    raw_owners = tc_owners()
    owners = []
    for owner in raw_owners['data']['owner']:
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


@logger
def tc_owners():
    tc = get_client()
    ro = RequestObject()
    ro.set_http_method('GET')
    ro.set_request_uri('/v2/owners')
    results = tc.api_request(ro)

    return results.json()


def tc_indicators_command():
    args = demisto.args()
    limit = int(args.get('limit', 500))
    owners = args.get('owners')
    ec, indicators, raw_response = tc_indicators(owners, limit)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': raw_response,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('ThreatConnect Indicators:', indicators, headerTransform=pascalToSpace),
        'EntryContext': ec
    })


@logger
def tc_indicators(owners, limit):
    tc = get_client()
    tc.set_api_result_limit(limit)
    ro = RequestObject()
    ro.set_http_method('GET')
    ro.set_request_uri('/v2/indicators?resultLimit={}'.format(limit))

    if owners is not None:
        ro.set_owner(owners)
        ro.set_owner_allowed(True)

    response = tc.api_request(ro).json()
    indicators = response['data']['indicator']
    ec, indicators = create_context(indicators, include_dbot_score=True)

    return ec, indicators, response


def tc_get_tags_command():
    raw_response = tc_get_tags()
    tags = [t['name'] for t in raw_response['data']['tag']]

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': raw_response,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('ThreatConnect Tags:', tags, headers='Name'),
        'EntryContext': {'TC.Tags': tags}
    })


@logger
def tc_get_tags():
    tc = get_client()
    ro = RequestObject()
    ro.set_http_method('GET')
    ro.set_request_uri('/v2/tags')

    return tc.api_request(ro).json()


def tc_tag_indicator_command():
    args = demisto.args()
    indicator = args['indicator']
    tag = args['tag']
    owners = args.get('owner')
    indicators = tc_tag_indicator(indicator, tag, owners)

    md = []
    for ind in indicators:
        md.append('Indicator {} with ID {}, was tagged with: {}'.format(indicator, ind.id, tag))

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': '\n'.join(md)
    })


def tc_tag_indicator(indicator, tag, owners=None):
    tc = get_client()
    indicators = tc.indicators()
    filter1 = indicators.add_filter()
    filter1.add_indicator(indicator)

    if owners is not None:
        owners = owners.split(",")
        filter1.add_owner(owners)

    indicators = indicators.retrieve()
    for indicator in indicators:
        indicator.add_tag(tag)
        indicator.commit()

    return indicators


def tc_get_indicator_command():
    args = demisto.args()
    owners = args.get('owners', demisto.params().get('defaultOrg'))
    if not owners:
        return_error('You must specify an owner in the command, or by using the Organization parameter.')
    rating_threshold = int(args.get('ratingThreshold', -1))
    confidence_threshold = int(args.get('confidenceThreshold', -1))
    indicator = args['indicator']

    ec, indicators, raw_indicators = tc_get_indicator(indicator, owners, rating_threshold, confidence_threshold)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': raw_indicators,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('ThreatConnect indicator for: {}'.format(indicator), indicators,
                                         headerTransform=pascalToSpace),
        'EntryContext': ec
    })


@logger
def tc_get_indicator(indicator, owners, rating_threshold, confidence_threshold):
    raw_indicators = get_indicators(indicator, owners=owners, rating_threshold=rating_threshold,
                                    confidence_threshold=confidence_threshold)
    ec, indicators = create_context(raw_indicators, include_dbot_score=True)

    return ec, indicators, raw_indicators


def tc_get_indicators_by_tag_command():
    args = demisto.args()
    tag = args['tag']
    owner = args.get('owner')
    response = tc_get_indicators_by_tag(tag, owner)
    raw_indicators = response['data']['indicator']
    ec, indicators = create_context(raw_indicators, include_dbot_score=True)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': response,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('ThreatConnect Indicators with tag: {}'.format(tag), indicators,
                                         headerTransform=pascalToSpace),
        'EntryContext': ec
    })


@logger
def tc_get_indicators_by_tag(tag, owner):
    tc = get_client()
    ro = RequestObject()
    ro.set_http_method('GET')
    cmd = '/v2/tags/{}/indicators'.format(tag)
    if owner is not None:
        cmd += '?owner={}'.format(owner)

    ro.set_request_uri(cmd)

    return tc.api_request(ro).json()


def tc_add_indicator_command():
    args = demisto.args()
    indicator = args['indicator']
    owner = args.get('owner', demisto.params().get('defaultOrg'))
    if not owner:
        return_error('You must specify an owner in the command, or by using the Organization parameter.')

    rating = int(args.get('rating', 0))
    confidence = int(args.get('confidence', 0))

    tc_add_indicator(indicator, owner, rating, confidence)
    # get the indicator for full object data
    raw_indicators = get_indicators(indicator)
    ec, indicators = create_context(raw_indicators)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': raw_indicators,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Created new indicator successfully:', indicators,
                                         headerTransform=pascalToSpace),
        'EntryContext': ec
    })


@logger
def tc_add_indicator(indicator, organization, rating=0, confidence=0):
    tc = get_client()
    indicators = tc.indicators()
    indicator = indicators.add(indicator, organization)
    indicator.set_rating(rating)
    indicator.set_confidence(confidence)

    return json.loads(indicator.commit().json)


def tc_create_incident_command():
    args = demisto.args()
    incident_name = args['incidentName']
    owner = args.get('owner', demisto.params()['defaultOrg'])
    if not owner:
        return_error('You must specify an owner in the command, or by using the Organization parameter.')

    event_date = args.get('eventDate', datetime.utcnow().isoformat().split('.')[0] + 'Z')
    tag = args.get('tag')
    security_label = args.get('securityLabel')
    description = args.get('description')

    raw_incident = tc_create_incident(incident_name, owner, event_date, tag, security_label, description)
    ec = {
        'ID': raw_incident['id'],
        'Name': raw_incident['name'],
        'Owner': raw_incident['ownerName'],
        'EventDate': raw_incident['eventDate'],
        'Tag': tag,
        'SecurityLabel': security_label
    }

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': raw_incident,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': 'Incident {} Created Successfully'.format(incident_name),
        'EntryContext': {
            'TC.Incident(val.ID && val.ID === obj.ID)': createContext([ec], removeNull=True)
        }
    })


@logger
def tc_create_incident(incident_name, owner, event_date, tag=None, security_label=None, description=None):
    tc = get_client()
    incidents = tc.incidents()
    incident = incidents.add(incident_name, owner)
    incident.set_event_date(event_date)
    if tag is not None:
        incident.add_tag(tag)
    if security_label is not None:
        incident.set_security_label(security_label)
    if description is not None:
        incident.add_attribute('Description', description)

    return json.loads(incident.commit().json)


def tc_fetch_incidents_command():
    args = demisto.args()
    incident_id = args.get('incidentId')
    incident_name = args.get('incidentName')
    owner = args.get('owner')

    raw_incidents = tc_fetch_incidents(incident_id, incident_name, owner)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': raw_incidents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Incidents:', raw_incidents, headerTransform=pascalToSpace),
        'EntryContext': {
            'TC.Incident(val.ID && val.ID === obj.ID)': createContext(raw_incidents, removeNull=True),
            'ThreatConnect.incidents': raw_incidents  # backward compatible
        }
    })


@logger
def tc_fetch_incidents(incident_id, incident_name, owner):
    tc = get_client()
    incidents = tc.incidents()
    if any((incident_id, owner, incident_name)):
        filter1 = incidents.add_filter()
        if incident_id is not None:
            filter1.add_id(int(incident_id))
        if owner is not None:
            filter1.add_owner(owner)
        if incident_name is not None:
            filter1.add_pf_name(incident_name)

    incidents.retrieve()
    return [json.loads(incident.json) for incident in incidents]


def tc_get_incident_associate_indicators_command():
    args = demisto.args()
    incident_id = int(args['incidentId'])
    owners = args.get('owner')
    if owners is not None:
        owners = owners.split(",")

    raw_indicators = tc_get_incident_associate_indicators(incident_id, owners)
    ec, indicators = create_context(raw_indicators, include_dbot_score=True)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': raw_indicators,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Incident Associated Indicators:', indicators, headerTransform=pascalToSpace),
        'EntryContext': ec
    })


@logger
def tc_get_incident_associate_indicators(incident_id, owners):
    tc = get_client()
    incidents = tc.incidents()
    _filter = incidents.add_filter()
    _filter.add_id(incident_id)

    incidents = incidents.retrieve()
    indicators = []
    for incident in incidents:
        for ind in incident.indicator_associations:
            if ind.type == 'File':
                indicators.append(ind.indicator['md5'])
            else:
                indicators.append(ind.indicator)
    if len(indicators) == 0:
        return []

    indicators_obj = tc.indicators()
    _filter = indicators_obj.add_filter()
    if owners is not None:
        _filter.add_owner(owners)
    for ind in indicators:
        _filter.add_indicator(ind)

    raw_indicators = indicators_obj.retrieve()
    return [json.loads(indicator.json) for indicator in raw_indicators]


def tc_incident_associate_indicator_command():
    args = demisto.args()
    incident_id = int(args['incidentId'])
    indicator = args['indicator']
    types = {
        'ADDRESSES': ResourceType.ADDRESSES,
        'EMAIL_ADDRESSES': ResourceType.EMAIL_ADDRESSES,
        'FILES': ResourceType.FILES,
        'HOSTS': ResourceType.HOSTS,
        'URLS': ResourceType.URLS,
    }
    indicator_type = types.get(args['indicatorType'], args['indicatorType'])
    owners = args.get('owner')
    if owners is not None:
        owners = owners.split(",")

    incidents = tc_incident_associate_indicator(incident_id, indicator_type, indicator, owners)
    md = []
    for inc in incidents:
        md.append('Incident {} with ID {}, was tagged with: {}'.format(inc['name'], inc['id'], indicator))

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': incidents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': '\n'.join(md),
        'EntryContext': {'TC.Incident(val.ID && val.ID === obj.ID)': createContext(incidents, removeNull=True)}
    })


@logger
def tc_incident_associate_indicator(incident_id, indicator_type, indicator, owners):
    tc = get_client()
    incidents = tc.incidents()
    filter1 = incidents.add_filter()
    filter1.add_id(incident_id)
    if owners is not None:
        filter1.add_owner(owners)
    raw_incidents = incidents.retrieve()

    incidents = []
    for incident in raw_incidents:
        incident.associate_indicator(indicator_type, indicator)
        incidents.append(json.loads(incident.commit().json))

    return incidents


def tc_update_indicator_command():
    args = demisto.args()
    indicator = args['indicator']
    rating = args.get('rating')
    confidence = args.get('confidence')
    size = args.get('size')
    dns_active = args.get('dnsActive')
    whois_active = args.get('whoisActive')
    false_positive = args.get('falsePositive', 'False') == 'True'
    observations = int(args.get('observations', 0))
    security_label = args.get('securityLabel')
    threat_assess_confidence = int(args.get('threatAssessConfidence', -1))
    threat_assess_rating = int(args.get('threatAssessRating', -1))

    raw_indicators = tc_update_indicator(indicator, rating=rating, confidence=confidence, size=size,
                                         dns_active=dns_active, whois_active=whois_active,
                                         false_positive=false_positive, observations=observations,
                                         security_label=security_label,
                                         threat_assess_confidence=threat_assess_confidence,
                                         threat_assess_rating=threat_assess_rating)
    ec, indicators = create_context(raw_indicators)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': raw_indicators,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': '\n'.join('Indicator {} Updated Successfully'.format(ind['ID']) for ind in indicators),
        'EntryContext': ec
    })


@logger
def tc_update_indicator(indicator, rating=None, confidence=None, size=None, dns_active=None, whois_active=None,
                        false_positive=False, observations=0, security_label=None, threat_assess_confidence=-1,
                        threat_assess_rating=-1):
    tc = get_client()
    indicators = tc.indicators()
    filter1 = indicators.add_filter()
    filter1.add_indicator(indicator)

    raw_indicators = []
    for ind in indicators.retrieve():
        if rating is not None:
            ind.set_rating(rating)
        if confidence is not None:
            ind.set_confidence(int(confidence))
        if false_positive:
            ind.add_false_positive()
        if observations != 0:
            ind.add_observation(observations)
        if security_label is not None:
            ind.add_security_label(security_label)
        if threat_assess_confidence != -1:
            ind.set_threat_assess_confidence(threat_assess_confidence)
        if threat_assess_rating != -1:
            ind.set_threat_assess_rating(threat_assess_rating)

        if ind.type == 'File' and size is not None:
            ind.add_size(size)
        if ind.type == 'Host' and dns_active is not None:
            ind.set_dns_active(dns_active)
        if ind.type == 'Host' and whois_active is not None:
            ind.set_whois_active(whois_active)

        raw_indicators.append(json.loads(ind.commit().json))

    return raw_indicators


def tc_delete_indicator_command():
    args = demisto.args()
    indicator = args['indicator']

    tc_delete_indicator(indicator)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': 'Indicator {} removed Successfully'.format(indicator)
    })


@logger
def tc_delete_indicator(indicator):
    tc = get_client()
    indicators = tc.indicators()
    filter1 = indicators.add_filter()
    filter1.add_indicator(indicator)
    indicators = indicators.retrieve()
    for ind in indicators:
        ind.delete()


def tc_delete_indicator_tag_command():
    args = demisto.args()
    indicator = args['indicator']
    tag = args['tag']

    indicators = tc_delete_indicator_tag(indicator, tag)
    raw_indicators = [json.loads(ind.json) for ind in indicators]
    ec, _ = create_context(raw_indicators)

    md = []
    for ind in indicators:
        md.append('Removed tag {} from indicator {}.'.format(tag, ind.indicator))
    if len(md) == 0:
        md.append('No indicators found')

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': raw_indicators,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': '\n'.join(md),
        'EntryContext': ec
    })


@logger
def tc_delete_indicator_tag(indicator, tag, owners=None):
    tc = get_client()
    indicators = tc.indicators()
    filter1 = indicators.add_filter()
    filter1.add_indicator(indicator)

    if owners is not None:
        owners = owners.split(",")
        filter1.add_owner(owners)

    indicators = indicators.retrieve()
    for indicator in indicators:
        indicator.delete_tag(tag)
        indicator.commit()

    return indicators


def tc_create_campaign_command():
    args = demisto.args()
    name = args['name']
    owner = args.get('owner', demisto.params()['defaultOrg'])
    if owner == '':
        return_error('You must specify an owner in the command, or by using the Organization parameter.')

    first_seen = args.get('firstSeen', datetime.utcnow().isoformat().split('.')[0] + 'Z')
    tag = args.get('tag')
    security_label = args.get('securityLabel')
    description = args.get('description')

    raw_campaign = tc_create_campaign(name, owner, first_seen, tag, security_label, description)
    ec = {
        'ID': raw_campaign['id'],
        'Name': raw_campaign['name'],
        'Owner': raw_campaign['owner']['name'],
        'FirstSeen': raw_campaign['firstSeen'],
        'Tag': tag,
        'SecurityLabel': security_label
    }

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': raw_campaign,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': 'Campaign {} Created Successfully'.format(name),
        'EntryContext': {
            'TC.Campaign(val.ID && val.ID === obj.ID)': createContext([ec], removeNull=True)
        }
    })


@logger
def tc_create_campaign(name, owner, first_seen, tag=None, security_label=None, description=None):
    tc = get_client()
    ro = RequestObject()
    ro.set_http_method('POST')
    ro.set_request_uri('/v2/groups/campaigns')
    body = {
        'name': name,
        'firstSeen': first_seen,
    }
    ro.set_body(json.dumps(body))
    response = tc.api_request(ro).json()

    if response.get('status') == 'Success':
        output = response.get('data', {}).get('campaign', {})
        event_id = output['id']
        if description is not None:
            # Associate Attribute description
            ro = RequestObject()
            ro.set_http_method('POST')
            ro.set_request_uri('/v2/groups/events/{}/attributes'.format(event_id))
            body = {
                'type': 'Description',
                'value': description,
                'displayed': 'true'
            }
            ro.set_body(json.dumps(body))
            tc.api_request(ro).json()

        return output
    else:
        return_error('Failed to create event')


def tc_create_event_command():
    args = demisto.args()
    name = args['name']
    event_date = args.get('EventDate', datetime.utcnow().isoformat().split('.')[0] + 'Z')
    status = args.get('status')
    owner = args.get('owner', demisto.params()['defaultOrg'])
    if owner == '':
        return_error('You must specify an owner in the command, or by using the Organization parameter.')

    description = args.get('description')
    tag = args.get('tag')

    raw_event = tc_create_event(name, owner, event_date, tag, status, description)
    ec = {
        'ID': raw_event['id'],
        'Name': raw_event['name'],
        'Owner': raw_event['owner']['name'],
        'Date': raw_event['eventDate'],
        'Tag': tag,
        'Status': status
    }

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': raw_event,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': 'Incident {} Created Successfully'.format(name),
        'EntryContext': {
            'TC.Event(val.ID && val.ID === obj.ID)': createContext([ec], removeNull=True)
        }
    })


def tc_create_event(name, owner, event_date, tag=None, status=None, description=None):
    tc = get_client()
    ro = RequestObject()
    ro.set_http_method('POST')
    ro.set_request_uri('/v2/groups/events')
    body = {
        'name': name,
        'eventDate': event_date,
        'status': status
    }
    ro.set_body(json.dumps(body))
    response = tc.api_request(ro).json()

    if response.get('status') == 'Success':
        output = response.get('data', {}).get('event', {})
        event_id = output['id']
        if description is not None:
            # Associate Attribute description
            ro = RequestObject()
            ro.set_http_method('POST')
            ro.set_request_uri('/v2/groups/events/{}/attributes'.format(event_id))
            body = {
                'type': 'Description',
                'value': description,
                'displayed': 'true'
            }
            ro.set_body(json.dumps(body))
            tc.api_request(ro).json()

        return output
    else:
        return_error('Failed to create event')


def tc_create_threat_command():
    args = demisto.args()
    name = args['name']
    date = args.get('dateAdded', datetime.utcnow().isoformat().split('.')[0] + 'Z')
    owner = args.get('owner', demisto.params()['defaultOrg'])
    if owner == '':
        return_error('You must specify an owner in the command, or by using the Organization parameter.')

    raw_threat = tc_create_threat(name, owner, date)
    ec = {
        'ID': raw_threat['id'],
        'Name': raw_threat['name']
    }

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': raw_threat,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': 'Threat {} Created Successfully'.format(name),
        'EntryContext': {
            'TC.Threat(val.ID && val.ID === obj.ID)': createContext([ec], removeNull=True)
        }
    })


def tc_create_threat(name, owner, date):
    tc = get_client()
    threats = tc.threats()
    threat = threats.add(name, owner)
    threat.set_date_added(date)

    return json.loads(threat.commit().json)


def tc_delete_group_command():
    args = demisto.args()
    group_id = int(args['groupID'])
    group_type = args['type']

    success = tc_delete_group(group_id, group_type.lower())
    if success:
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['text'],
            'Contents': '{} {} deleted Successfully'.format(group_type.lower(), group_id)
        })
    else:
        return_error('Failed to delete {} {}'.format(group_type, group_id))


def tc_delete_group(group_id, group_type):
    tc = get_client()
    ro = RequestObject()
    ro.set_http_method('DELETE')
    ro.set_request_uri('/v2/groups/{}/{}'.format(group_type, group_id))
    response = tc.api_request(ro).json()

    return response['status'] == 'Success'


def tc_add_group_attribute_request(group_type, group_id, attribute_type, attribute_value):
    tc = get_client()
    ro = RequestObject()
    ro.set_http_method('POST')
    ro.set_request_uri('/v2/groups/{}/{}/attributes'.format(group_type, group_id))
    body = {
        'type': attribute_type,
        'value': attribute_value,
        'displayed': 'true'
    }
    ro.set_body(json.dumps(body))
    response = tc.api_request(ro).json()

    return response


def tc_add_group_attribute():
    group_id = int(demisto.args().get('group_id'))
    group_type = demisto.args().get('group_type')
    attribute_type = demisto.args().get('attribute_type')
    attribute_value = demisto.args().get('attribute_value')
    headers = ['Type', 'Value', 'ID', 'DateAdded', 'LastModified']
    attribute = tc_add_group_attribute_request(group_type, group_id, attribute_type, attribute_value)
    data = attribute.get('data').get('attribute')
    contents = {
        'Type': data.get('type'),
        'Value': data.get('value'),
        'ID': data.get('id'),
        'DateAdded': data.get('dateAdded'),
        'LastModified': data.get('lastModified')
    }
    context = {
        'TC.Group(val.ID && val.ID === obj.ID)': contents
    }

    return_outputs(
        tableToMarkdown('The attribute was added successfully to group {}'.format(group_id), contents, headers,
                        removeNull=True),
        context,
        attribute
    )


def add_group_security_label_request(group_type, group_id, security_label):
    tc = get_client()
    ro = RequestObject()
    ro.set_http_method('POST')
    ro.set_request_uri('/v2/groups/{}/{}/securityLabels/{}'.format(group_type, group_id, security_label))

    response = tc.api_request(ro).json()

    return response.get('status') == 'Success'


def add_group_security_label():
    group_id = int(demisto.args().get('group_id'))
    group_type = demisto.args().get('group_type')
    security_label = demisto.args().get('security_label_name')

    add_group_security_label_request(group_type, group_id, security_label)

    demisto.results('The security label {} was added successfully to {} {}'.format(security_label, group_type,
                                                                                   group_id))


def add_group_tags_request(group_type, group_id, tag_name):
    tc = get_client()
    ro = RequestObject()
    ro.set_http_method('POST')
    ro.set_request_uri('/v2/groups/{}/{}/tags/{}'.format(group_type, group_id, tag_name))

    response = tc.api_request(ro).json()

    return response.get('status') == 'Success'


def add_group_tag():
    group_id = int(demisto.args().get('group_id'))
    group_type = demisto.args().get('group_type')
    tag_name = demisto.args().get('tag_name')

    add_group_tags_request(group_type, group_id, tag_name)

    demisto.results('The tag {} was added successfully to group {} {}'.format(tag_name, group_type, group_id))


def get_events_request():
    tc = get_client()
    ro = RequestObject()
    ro.set_http_method('GET')
    ro.set_request_uri('/v2/groups/events')

    return tc.api_request(ro).json()


def tc_get_events():
    raw_response = get_events_request()
    data = raw_response.get('data', {}).get('event', [])
    content = []
    headers = ['ID', 'Name', 'OwnerName', 'EventDate', 'DateAdded', 'Status']

    for event in data:
        content.append({
            'ID': event.get('id'),
            'Name': event.get('name'),
            'OwnerName': event.get('ownerName'),
            'DateAdded': event.get('dateAdded'),
            'EventDate': event.get('eventDate'),
            'Status': event.get('status')
        })
    context = {
        'TC.Event(val.ID && val.ID === obj.ID)': content
    }

    return_outputs(
        tableToMarkdown('ThreatConnect Events', content, headers, removeNull=True),
        context,
        raw_response
    )


def tc_get_indicator_types_request():
    tc = get_client()
    ro = RequestObject()
    ro.set_http_method('GET')
    ro.set_request_uri('/v2/types/indicatorTypes')

    return tc.api_request(ro).json()


def tc_get_indicator_types():
    raw_response = tc_get_indicator_types_request()
    data = raw_response.get('data', {}).get('indicatorType', [])
    content = []
    headers = ['Name', 'Custom', 'Parsable', 'ApiBranch', 'CasePreference', 'value1Label', 'Value1Type']

    for type_ in data:
        content.append({
            'Custom': type_.get('custom'),
            'Name': type_.get('name'),
            'Parsable': type_.get('parsable'),
            'ApiBranch': type_.get('apiBranch'),
            'ApiEntity': type_.get('apiEntity'),
            'CasePreference': type_.get('casePreference'),
            'Value1Label': type_.get('value1Label'),
            'Value1Type': type_.get('value1Type')
        })
    context = {
        'TC.IndicatorType(val.Name && val.Name === obj.Name)': content
    }

    return_outputs(
        tableToMarkdown('ThreatConnect indicator types', content, headers, removeNull=True),
        context,
        raw_response
    )


def associate_indicator_request(indicator_type, indicator, group_type, group_id):
    tc = get_client()
    ro = RequestObject()
    ro.set_http_method('POST')
    ro.set_request_uri('/v2/indicators/{}/{}/groups/{}/{}'.format(indicator_type, indicator, group_type, group_id))
    response = tc.api_request(ro).json()

    return response


def associate_indicator():
    group_id = int(demisto.args().get('group_id'))
    group_type = demisto.args().get('group_type')
    indicator_type = demisto.args().get('indicator_type')
    indicator = demisto.args().get('indicator')

    response = associate_indicator_request(indicator_type, indicator, group_type, group_id)

    if response.get('status') == 'Success':
        contents = {
            'IndicatorType': indicator_type,
            'Indicator': indicator,
            'GroupType': group_type,
            'GroupID': group_id
        }
    else:
        return_error(response.get('message'))

    context = {
        'TC.Group(val.Indicator && val.Indicator === obj.Indicator)': contents
    }

    return_outputs(
        tableToMarkdown('The indicator was associated successfully', contents, removeNull=True),
        context
    )


def get_groups_request(group_type):
    tc = get_client()
    ro = RequestObject()
    ro.set_http_method('GET')
    ro.set_request_uri('/v2/groups/{}'.format(group_type))

    return tc.api_request(ro).json()


def tc_get_groups():
    group_type = demisto.args().get('group_type')
    raw_response = get_groups_request(group_type)
    headers = ['ID', 'Name', 'OwnerName', 'EventDate', 'DateAdded', 'Status']
    if group_type == 'adversaries':
        data = raw_response.get('data', {}).get('adversarie', {})
    if group_type == 'campaigns':
        data = raw_response.get('data', {}).get('campaign', {})
    if group_type == 'documents':
        data = raw_response.get('data', {}).get('document', {})
    if group_type == 'emails':
        data = raw_response.get('data', {}).get('email', {})
    if group_type == 'events':
        data = raw_response.get('data', {}).get('event', {})
    if group_type == 'incidents':
        data = raw_response.get('data', {}).get('incident', {})
    if group_type == 'intrusionSets':
        data = raw_response.get('data', {}).get('intrusionSet', {})
    if group_type == 'reports':
        data = raw_response.get('data', {}).get('report', {})
    if group_type == 'signatures':
        data = raw_response.get('data', {}).get('signature', {})
    if group_type == 'threats':
        data = raw_response.get('data', {}).get('threat', {})

    content = []

    for group in data:
        content.append({
            'ID': group.get('id'),
            'Name': group.get('name'),
            'OwnerName': group.get('ownerName'),
            'DateAdded': group.get('dateAdded'),
            'EventDate': group.get('eventDate'),
            'Status': group.get('status')
        })
    context = {
        'TC.Group(val.ID && val.ID === obj.ID)': content
    }

    return_outputs(
        tableToMarkdown('ThreatConnect {}'.format(group_type), content, headers, removeNull=True),
        context,
        raw_response
    )


def get_group_request(group_type, group_id):
    tc = get_client()
    ro = RequestObject()
    ro.set_http_method('GET')
    ro.set_request_uri('/v2/groups/{}/{}'.format(group_type, group_id))

    return tc.api_request(ro).json()


def get_group():
    """
    Retrieve a single Group
    """
    group_type = demisto.args().get('group_type')
    try:
        group_id = int(demisto.args().get('group_id'))
    except TypeError as t:
        return_error('group_id must be a number', t)

    response = get_group_request(group_type, group_id).get('data', {})
    if group_type == 'adversaries':
        data = response.get('adversarie', {})
    if group_type == 'campaigns':
        data = response.get('campaign', {})
    if group_type == 'documents':
        data = response.get('document', {})
    if group_type == 'emails':
        data = response.get('email', {})
    if group_type == 'events':
        data = response.get('event', {})
    if group_type == 'incidents':
        data = response.get('incident', {})
    if group_type == 'intrusionSets':
        data = response.get('intrusionSet', {})
    if group_type == 'reports':
        data = response.get('report', {})
    if group_type == 'signatures':
        data = response.get('signature', {})
    if group_type == 'threats':
        data = response.get('threat', {})

    owner = {
        'Name': data.get('owner').get('name'),
        'ID': data.get('owner').get('id'),
        'Type': data.get('owner').get('type')
    }
    contents = {
        'ID': data.get('id'),
        'Name': data.get('name'),
        'Owner': owner,
        'DateAdded': data.get('dateAdded'),
        'EventDate': data.get('eventDate'),
        'Status': data.get('status')
    }

    context = {
        'TC.Group(val.ID && val.ID === obj.ID)': contents
    }

    return_outputs(
        tableToMarkdown('ThreatConnect Group information', contents, removeNull=True),
        context,
        response
    )


def get_group_attributes_request(group_type, group_id):
    tc = get_client()
    ro = RequestObject()
    ro.set_http_method('GET')
    ro.set_request_uri('/v2/groups/{}/{}/attributes'.format(group_type, group_id))

    return tc.api_request(ro).json()


def get_group_attributes():
    """
    Retrieve a Group's Attributes
    """
    group_type = demisto.args().get('group_type')
    try:
        group_id = int(demisto.args().get('group_id'))
    except TypeError as t:
        return_error('group_id must be a number', t)
    contents = []
    headers = ['AttributeID', 'Type', 'Value', 'DateAdded', 'LastModified', 'Displayed']
    response = get_group_attributes_request(group_type, group_id)
    data = response.get('data', {}).get('attribute', [])

    if response.get('status') == 'Success':
        for attribute in data:
            contents.append({
                'GroupID': group_id,
                'AttributeID': attribute.get('id'),
                'Type': attribute.get('type'),
                'Value': attribute.get('value'),
                'DateAdded': attribute.get('dateAdded'),
                'LastModified': attribute.get('lastModified'),
                'Displayed': attribute.get('displayed')
            })

    else:
        return_error(response.get('message'))

    context = {
        'TC.Group.Attribute(val.GroupID && val.GroupID === obj.GroupID && val.AttributeID && val.AttributeID ==='
        ' obj.AttributeID)': contents
    }

    return_outputs(
        tableToMarkdown('ThreatConnect Group Attributes', contents, headers, removeNull=True),
        context,
        response
    )


def get_group_security_labels_request(group_type, group_id):
    tc = get_client()
    ro = RequestObject()
    ro.set_http_method('GET')
    ro.set_request_uri('/v2/groups/{}/{}/securityLabels'.format(group_type, group_id))

    return tc.api_request(ro).json()


def get_group_security_labels():
    """
    Retrieve a Group's Security Labels
    """
    group_type = demisto.args().get('group_type')
    try:
        group_id = int(demisto.args().get('group_id'))
    except TypeError as t:
        return_error('group_id must be a number', t)
    contents = []
    headers = ['Name', 'Description', 'DateAdded']
    response = get_group_security_labels_request(group_type, group_id)
    data = response.get('data', {}).get('securityLabel', [])

    if response.get('status') == 'Success':
        for security_label in data:
            contents.append({
                'GroupID': group_id,
                'Name': security_label.get('name'),
                'Description': security_label.get('description'),
                'DateAdded': security_label.get('dateAdded')
            })

    else:
        return_error(response.get('message'))

    context = {
        'TC.Group.SecurityLabel(val.GroupID && val.GroupID === obj.GroupID && val.Name && val.Name === '
        'obj.Name)': contents
    }

    return_outputs(
        tableToMarkdown('ThreatConnect Group Security Labels', contents, headers, removeNull=True),
        context
    )


def get_group_tags_request(group_type, group_id):
    tc = get_client()
    ro = RequestObject()
    ro.set_http_method('GET')
    ro.set_request_uri('/v2/groups/{}/{}/tags'.format(group_type, group_id))

    return tc.api_request(ro).json()


def get_group_tags():
    """
    Retrieve the Tags for a Group
    """
    group_type = demisto.args().get('group_type')
    try:
        group_id = int(demisto.args().get('group_id'))
    except TypeError as t:
        return_error('group_id must be a number', t)
    contents = []
    context_entries = []
    response = get_group_tags_request(group_type, group_id)
    data = response.get('data', {}).get('tag', [])

    if response.get('status') == 'Success':
        for tags in data:
            contents.append({
                'Name': tags.get('name')
            })

            context_entries.append({
                'GroupID': group_id,
                'Name': tags.get('name')
            })
    else:
        return_error(response.get('message'))

    context = {
        'TC.Group.Tag(val.GroupID && val.GroupID === obj.GroupID && val.Name && val.Name === obj.Name)': context_entries
    }

    return_outputs(
        tableToMarkdown('ThreatConnect Group Tags', contents, removeNull=True),
        context,
        response
    )


def get_group_indicator_request(group_type, group_id):
    tc = get_client()
    ro = RequestObject()
    ro.set_http_method('GET')
    ro.set_request_uri('/v2/groups/{}/{}/indicators'.format(group_type, group_id))

    return tc.api_request(ro).json()


def get_group_indicator():
    """
    View Indicators associated with a given Group
    """
    group_type = demisto.args().get('group_type')
    try:
        group_id = int(demisto.args().get('group_id'))
    except TypeError as t:
        return_error('group_id must be a number', t)
    contents = []
    response = get_group_indicator_request(group_type, group_id)
    data = response.get('data', {}).get('indicator', [])

    if response.get('status') == 'Success':
        for indicator in data:
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

    else:
        return_error(response.get('message'))

    context = {
        'TC.Group.Indicator(val.GroupID && val.GroupID === obj.GroupID && val.IndicatorID && val.IndicatorID === '
        'obj.IndicatorID)': contents
    }

    return_outputs(
        tableToMarkdown('ThreatConnect Group Indicators', contents, removeNull=True),
        context,
        response
    )


def get_group_associated_request(group_type, group_id):
    tc = get_client()
    ro = RequestObject()
    ro.set_http_method('GET')
    ro.set_request_uri('/v2/groups/{}/{}/groups'.format(group_type, group_id))

    return tc.api_request(ro).json()


def get_group_associated():
    """
    View Indicators associated with a given Group
    """
    group_type = demisto.args().get('group_type')
    try:
        group_id = int(demisto.args().get('group_id'))
    except TypeError as t:
        return_error('group_id must be a number', t)
    contents = []
    headers = ['GroupID', 'Name', 'Type', 'OwnerName', 'DateAdded']
    response = get_group_associated_request(group_type, group_id)
    data = response.get('data', {}).get('group', [])

    if response.get('status') == 'Success':
        for group in data:
            contents.append({
                'GroupID': group.get('id'),
                'Name': group.get('name'),
                'Type': group.get('type'),
                'DateAdded': group.get('dateAdded'),
                'OwnerName': group.get('ownerName')
            })

    else:
        return_error(response.get('message'))

    context = {
        'TC.Group.AssociatedGroup(val.GroupID && val.GroupID === obj.GroupID)': contents
    }

    return_outputs(
        tableToMarkdown('ThreatConnect Associated Groups', contents, headers, removeNull=True),
        context,
        response
    )


def associate_group_to_group_request(group_type, group_id, associated_group_type, associated_group_id):
    tc = get_client()
    ro = RequestObject()
    ro.set_http_method('POST')
    ro.set_request_uri('/v2/groups/{}/{}/groups/{}/{}'.format(group_type, group_id, associated_group_type,
                                                              associated_group_id))

    return tc.api_request(ro).json()


def associate_group_to_group():
    """
    Associate one Group with another
    """

    group_type = demisto.args().get('group_type')
    associated_group_type = demisto.args().get('associated_group_type')
    try:
        group_id = int(demisto.args().get('group_id'))
    except TypeError as t:
        return_error('group_id must be a number', t)
    try:
        associated_group_id = int(demisto.args().get('associated_group_id'))
    except TypeError as t:
        return_error('associated_group_id must be a number', t)

    response = associate_group_to_group_request(group_type, group_id, associated_group_type, associated_group_id)

    if response.get('status') == 'Success':
        context_entries = {
            'GroupID': group_id,
            'GroupType': group_type,
            'AssociatedGroupID': associated_group_id,
            'AssociatedGroupType': associated_group_type
        }
        context = {
            'TC.Group.AssociatedGroup(val.GroupID && val.GroupID === obj.GroupID)': context_entries
        }
        return_outputs('The group {} was associated successfully.'.format(associated_group_id),
                       context,
                       response)
    else:
        return_error(response.get('message'))


def create_document_group_request(contents, file_name, name, owner, res, malware, password, security_label,
                                  description):
    tc = get_client()
    documents = tc.documents()

    document = documents.add(name, owner)
    document.set_file_name(file_name)

    # upload the contents of the file into the Document
    document.upload(contents)
    if malware:
        document.set_malware(True)
        document.set_password(password)
    if security_label:
        document.set_security_label(security_label)
    if description:
        document.add_attribute('Description', description)

    return json.loads(document.commit().json)


def create_document_group():
    file_name = demisto.args().get('file_name')
    name = demisto.args().get('name')
    malware = bool(strtobool(demisto.args().get('malware', False)))
    password = demisto.args().get('password')
    res = demisto.getFilePath(demisto.args()['entry_id'])
    owner = demisto.args().get('owner', demisto.params().get('defaultOrg'))
    if not owner:
        return_error('You must specify an owner in the command, or by using the Organization parameter.')

    security_label = demisto.args().get('securityLabel')
    description = demisto.args().get('description')

    # open a file handle for a local file and read the contents thereof
    f = open(res['path'], 'rb')
    contents = f.read()

    raw_document = create_document_group_request(contents, file_name, name, owner, res, malware, password,
                                                 security_label, description)
    content = {
        'ID': raw_document.get('id'),
        'Name': raw_document.get('name'),
        'Owner': raw_document.get('ownerName'),
        'EventDate': raw_document.get('eventDate'),
        'Description': description,
        'SecurityLabel': security_label
    }
    context = {
        'TC.Group(val.ID && val.ID === obj.ID)': content
    }
    return_outputs(tableToMarkdown('ThreatConnect document group was created successfully', content, removeNull=True),
                   context,
                   raw_document)


def get_document_request(document_id):

    tc = get_client()
    documents = tc.documents()
    # set a filter to retrieve only the Document with ID: 123456
    filter1 = documents.add_filter()
    filter1.add_id(document_id)
    try:
        # retrieve the Document
        documents.retrieve()
    except RuntimeError as e:
        return_error('Error: {0}'.format(str(e)))

    # iterate through the retrieved Documents (in this case there should only be one) and print its properties
    for document in documents:
        document.download()
        if document.contents is not None:
            return document
        else:
            return_error('No document was found.')


def download_document():
    """
    Download the contents of a Document
    """
    try:
        document_id = int(demisto.args().get('document_id'))
    except TypeError as t:
        return_error('document_id must be a number', t)
    document = get_document_request(document_id)

    file_name = document.file_name
    file_content = document.contents
    demisto.results(fileResult(file_name, file_content))


def test_integration():
    tc = get_client()
    owners = tc.owners()
    owners.retrieve()
    demisto.results('ok')


''' EXECUTION CODE '''
COMMANDS = {
    'test-module': test_integration,
    'ip': ip_command,
    'url': url_command,
    'file': file_command,
    'domain': domain_command,

    'tc-owners': tc_owners_command,
    'tc-indicators': tc_indicators_command,
    'tc-get-tags': tc_get_tags_command,
    'tc-tag-indicator': tc_tag_indicator_command,
    'tc-get-indicator': tc_get_indicator_command,
    'tc-get-indicators-by-tag': tc_get_indicators_by_tag_command,
    'tc-add-indicator': tc_add_indicator_command,

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
    'tc-add-group-attribute': tc_add_group_attribute,
    'tc-create-threat': tc_create_threat_command,
    'tc-delete-group': tc_delete_group_command,
    'tc-get-groups': tc_get_groups,
    'tc-add-group-security-label': add_group_security_label,
    'tc-add-group-tag': add_group_tag,
    'tc-get-indicator-types': tc_get_indicator_types,
    'tc-group-associate-indicator': associate_indicator,
    'tc-create-document-group': create_document_group,
    'tc-get-group': get_group,
    'tc-get-group-attributes': get_group_attributes,
    'tc-get-group-security-labels': get_group_security_labels,
    'tc-get-group-tags': get_group_tags,
    'tc-download-document': download_document,
    'tc-get-group-indicators': get_group_indicator,
    'tc-get-associated-groups': get_group_associated,
    'tc-associate-group-to-group': associate_group_to_group
}

try:
    command_func = demisto.command()
    LOG('command is %s' % (demisto.command(),))
    if command_func in COMMANDS.keys():
        COMMANDS[command_func]()

except Exception as e:
    LOG(e.message)
    LOG.print_log()
    return_error('error has occurred: {}'.format(e.message, ))
