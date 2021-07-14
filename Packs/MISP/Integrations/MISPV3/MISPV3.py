# type: ignore
from typing import Union, List, Dict
from urllib.parse import urlparse

import requests
from pymisp import ExpandedPyMISP, PyMISPError, MISPObject, MISPSighting, MISPEvent
from pymisp.tools import GenericObjectGenerator
import copy
from pymisp.tools import FileObject

from CommonServerPython import *

logging.getLogger("pymisp").setLevel(logging.CRITICAL)


def warn(*args):
    """
    Do nothing with warnings
    """
    pass


# Disable requests warnings
requests.packages.urllib3.disable_warnings()

# Disable python warnings
warnings.warn = warn

''' GLOBALS/PARAMS '''
verify = not demisto.params().get('insecure')
proxies = handle_proxy()  # type: ignore
misp_api_key = demisto.params().get('api_key')
misp_url = demisto.params().get('url')
PYMISP = ExpandedPyMISP(url=misp_url, key=misp_api_key, ssl=verify, proxies=proxies)

INTEGRATION_NAME = "MISP V3"

PREDEFINED_FEEDS = {
    'CIRCL': {'name': 'CIRCL OSINT Feed',
              'url': 'https://www.circl.lu/doc/misp/feed-osint',
              'format': 'misp',
              'input': 'network'},
    'Botvrij.eu': {'name': 'The Botvrij.eu Data',
                   'url': 'http://www.botvrij.eu/data/feed-osint',
                   'format': 'misp',
                   'input': 'network'}
}

THREAT_LEVELS_NUMBERS = {
    'high': 1,
    'medium': 2,
    'low': 3,
    'undefined': 4
}

ENTITIESDICT = {
    'deleted': 'Deleted',
    'category': 'Category',
    'comment': 'Comment',
    'uuid': 'UUID',
    'sharing_group_id': 'SharingGroupID',
    'timestamp': 'Timestamp',
    'to_ids': 'ToIDs',
    'value': 'Value',
    'event_id': 'EventID',
    'ShadowAttribute': 'ShadowAttribute',
    'disable_correlation': 'DisableCorrelation',
    'distribution': 'Distribution',
    'type': 'Type',
    'id': 'ID',
    'date': 'Date',
    'info': 'Info',
    'published': 'Published',
    'attribute_count': 'AttributeCount',
    'proposal_email_lock': 'ProposalEmailLock',
    'locked': 'Locked',
    'publish_timestamp': 'PublishTimestamp',
    'event_creator_email': 'EventCreatorEmail',
    'name': 'Name',
    'analysis': 'Analysis',
    'threat_level_id': 'ThreatLevelID',
    'old_id': 'OldID',
    'org_id': 'OrganisationID',
    'Org': 'Organisation',
    'Orgc': 'OwnerOrganisation',
    'orgc_uuid': 'OwnerOrganisation.UUID',
    'orgc_id': 'OwnerOrganisation.ID',
    'orgc_name': 'OwnerOrganisation.Name',
    'event_uuid': 'EventUUID',
    'proposal_to_delete': 'ProposalToDelete',
    'description': 'Description',
    'version': 'Version',
    'Object': 'Object',
    'object_id': 'ObjectID',
    'object_relation': 'ObjectRelation',
    'template_version': 'TemplateVersion',
    'template_uuid': 'TemplateUUID',
    'meta-category': 'MetaCategory',
    'decay_score': 'DecayScore',
    'first_seen': 'first_seen',
    'last_seen': 'last_seen'
}

ANALYSIS_NUMBERS = {
    'initial': 0,
    'ongoing': 1,
    'completed': 2
}

DISTRIBUTION_NUMBERS = {
    'Your_organisation_only': 0,
    'This_community_only': 1,
    'Connected_communities': 2,
    'All_communities': 3,
    'Inherit_event': 5
}

SIGHTING_TO_TYPE_MAP = {
    'sighting': 0,
    'false_positive': 1,
    'expiration': 2
}

SIGHTING_FROM_TYPE_MAP = {
    '0': 'sighting',
    '1': 'false_positive',
    '2': 'expiration'
}

DBOT_SCORE_TYPE_MAP = {
    'FILE': DBotScoreType.FILE,
    'URL': DBotScoreType.URL,
    'DOMAIN': DBotScoreType.DOMAIN,
    'IP': DBotScoreType.IP,
    'EMAIL': DBotScoreType.EMAIL,
}

DOMAIN_REGEX = (
    r"([a-z¡-\uffff0-9](?:[a-z¡-\uffff0-9-]{0,61}"
    "[a-z¡-\uffff0-9])?(?:\\.(?!-)[a-z¡-\uffff0-9-]{1,63}(?<!-))*"
    "\\.(?!-)(?!(jpg|jpeg|exif|tiff|tif|png|gif|otf|ttf|fnt|dtd|xhtml|css"
    "|html)$)(?:[a-z¡-\uffff-]{2,63}|xn--[a-z0-9]{1,59})(?<!-)\\.?$"
    "|localhost)"
)
MISP_SEARCH_ARGUMENTS = [
    'value',
    'type',
    'category',
    'org',
    'tags',
    'from',
    'to',
    'event_id',
    'uuid',
    'to_ids',
    'last',
    'include_decay_score',
    'include_sightings',
    'include_correlations',
    'limit',
    'page',
    'enforceWarninglist',
]

EVENT_FIELDS = [
    'id',
    'orgc_id',
    'org_id',
    'date',
    'threat_level_id',
    'info',
    'published',
    'uuid',
    'analysis',
    'attribute_count',
    'timestamp',
    'distribution',
    'proposal_email_lock',
    'locked',
    'publish_timestamp',
    'sharing_group_id',
    'disable_correlation',
    'event_creator_email',
    'Org',
    'Orgc',
    'RelatedEvent',
    'Galaxy',
    'Tag',
    'decay_score',
    'Object'
]

ATTRIBUTE_FIELDS = [
    'id',
    'event_id',
    'object_id',
    'object_relation',
    'category',
    'type',
    'to_ids',
    'uuid',
    'timestamp',
    'distribution',
    'sharing_group_id',
    'comment',
    'deleted',
    'disable_correlation',
    'first_seen',
    'last_seen',
    'value',
    'Event',
    'Object',
    'Galaxy',
    'Tag',
    'decay_score',
    'Sighting',
]


def extract_error(error: list) -> List[dict]:
    """Extracting errors

    Args:
        error: list of responses from error section

    Returns:
        List[Dict[str, any]]: filtered response

    Examples:
        extract_error([
            (403,
                {
                    'name': 'Could not add object',
                    'message': 'Could not add object',
                    'url': '/objects/add/156/',
                    'errors': 'Could not save object as at least one attribute has failed validation (ip). \
                    {"value":["IP address has an invalid format."]}'
                }
            )
        ])

        Response:
        [{
            'code': 403,
            'message': 'Could not add object',
            'errors': 'Could not save object as at least one attribute has failed validation (ip). \
            {"value":["IP address has an invalid format."]}'
        }]

    """
    return [{
        'code': err[0],
        'message': err[1].get('message'),
        'errors': err[1].get('errors')
    } for err in error]


def build_list_from_dict(args: dict) -> List[dict]:
    """

    Args:
        args: dictionary describes MISP object

    Returns:
        list: list containing dicts that GenericObjectGenerator can take.

    Examples:
        >>> {'ip': '8.8.8.8', 'domain': 'google.com'}
        [{'ip': '8.8.8.8'}, {'domain': 'google.com'}]
    """
    return [{k: v} for k, v in args.items()]


def build_generic_object(template_name: str, args: List[dict]) -> GenericObjectGenerator:
    """

    Args:
        template_name: template name as described in https://github.com/MISP/misp-objects
        args: arguments to create the generic object

    Returns:
        GenericObjectGenerator: object created in MISP

    Example:
        args should look like:
             [{'analysis_submitted_at': '2018-06-15T06:40:27'},
             {'threat_score': {value=95, to_ids=False}},
             {'permalink': 'https://panacea.threatgrid.com/mask/samples/2e445ef5389d8b'},
             {'heuristic_raw_score': 7.8385159793597}, {'heuristic_score': 96},
             {'original_filename': 'juice.exe'}, {'id':  '2e445ef5389d8b'}] # guardrails-disable-line
    """
    misp_object = GenericObjectGenerator(template_name)
    misp_object.generate_attributes(args)
    return misp_object


def convert_timestamp(timestamp: Union[str, int]) -> str:
    """
    Gets a timestamp from MISP response (1546713469) and converts it to human readable format
    """
    return datetime.utcfromtimestamp(int(timestamp)).strftime('%Y-%m-%d %H:%M:%S') if timestamp else ""


def replace_keys(obj_to_build: Union[dict, list, str]) -> Union[dict, list, str]:
    """
    Replacing keys from MISP's format to Demisto's (as appear in ENTITIESDICT)

    Args:
        obj_to_build (Union[dict, list, str]): object to replace keys in

    Returns:
        Union[dict, list, str]: same object type that got in
    """
    if isinstance(obj_to_build, list):
        return [replace_keys(item) for item in obj_to_build]
    if isinstance(obj_to_build, dict):
        return {
            (ENTITIESDICT[key] if key in ENTITIESDICT else key): replace_keys(value)
            for key, value in obj_to_build.items()
        }
    return obj_to_build


def reputation_command_to_human_readable(outputs, score, events_to_human_readable):
    found_tag_id, found_tag_name = "", ""
    for event in events_to_human_readable:
        found_tag_id = event.pop('Tag_ID')
        found_tag_name = event.pop('Tag_Name')
    return {
        'Attribute Type': outputs.get('Type'),
        'Dbot Score': score,
        'Attribute Value': outputs.get('Value'),
        'Attribute Category': outputs.get('Category'),
        'Timestamp': convert_timestamp(outputs.get('Timestamp')),
        'Events with the scored tag': events_to_human_readable,
        'Scored Tag ID': found_tag_id,
        'Scored Tag Name': found_tag_name,
    }


def limit_tag_output(attribute_dict, is_event_level):
    """
    limits the tag list to the ID and Name fields.
    In addition, returns set of the found tag ids.
    """
    output = []
    tag_set_ids = set()
    tags_list = attribute_dict.get('Tag', [])
    for tag in tags_list:
        is_event_tag = tag.get('inherited', 0)
        tag_id = tag.get('id')
        if is_event_level:
            tag_set_ids.add(tag_id)
        else:  # attribute level
            if not is_event_tag:
                tag_set_ids.add(tag_id)
        output.append({'ID': tag_id, 'Name': tag.get('name')})
    return output, tag_set_ids


def parse_response_reputation_command(response, malicious_tag_ids, suspicious_tag_ids):
    """
    After getting all the attributes that match the required indicator value, this function parses the response.
    This function combines all of the attributes that found with their event's object into one json object (that will
    be returned to the context data). In addition the function returns the indicator score and the tag (id) which
    caused the indicator to get that score.
    Please see an example for a response in test_data/reputation_command_response.json
    Please see an example for a parsed output in test_data/reputation_command_outputs.json
    """
    attributes_list = response.get('Attribute')
    attributes_tag_ids, event_tag_ids = set(), set()
    if not attributes_list:
        return None
    first_attribute = attributes_list[0]
    related_events, attribute_tags_from_related, event_tags_from_related = get_full_related_event_objects(
        attributes_list)
    attributes_tag_ids.update(attribute_tags_from_related)
    event_tag_ids.update(event_tags_from_related)

    attribute_related_events = first_attribute.get('RelatedAttribute')
    if attribute_related_events:
        for event in attribute_related_events:
            if event.get('Event'):
                event['Event'] = related_events[event.get('event_id')].get('Event', {})
                event['Tag'] = related_events[event.get('event_id')].get('Tag', [])
    first_attribute['Event']['Tag'], first_attribute_event_tags = limit_tag_output(first_attribute.get('Event'), True)
    event_tag_ids.update(first_attribute_event_tags)

    first_attribute['Tag'], first_attribute_tags = limit_tag_output(first_attribute, False)
    attributes_tag_ids.update(first_attribute_tags)

    score, found_tag = get_score_by_tags(attribute_tags_ids=attributes_tag_ids, event_tags_ids=event_tag_ids,
                                         malicious_tag_ids=malicious_tag_ids, suspicious_tag_ids=suspicious_tag_ids)

    first_attribute = replace_keys(first_attribute)  # this is the outputs (Attribute)
    return first_attribute, score, found_tag


def get_full_related_event_objects(attributes_list):
    """
    Going through the related attribute (actually events) to get their events' objects and attribute's tags.
    """
    related_events = {}
    attributes_tag_set_ids, event_tag_set_ids = set(), set()
    if len(attributes_list) == 1:
        return related_events, attributes_tag_set_ids, event_tag_set_ids
    attributes_list = attributes_list[1:]  # only if len(attributes_list) > 1
    for attribute in attributes_list:
        event = attribute.get('Event')
        attribute_tag_list = attribute.get('Tag')
        attribute_tags = []
        if attribute_tag_list:
            attribute_tags, current_attribute_tags = limit_tag_output(attribute, False)
            attributes_tag_set_ids.update(current_attribute_tags)
        if event:
            if event.get('Tag'):
                event['Tag'], current_event_tags = limit_tag_output(event, True)
                event_tag_set_ids.update(current_event_tags)
            related_events[event.get('id')] = {"Event": event, "Tag": attribute_tags}

    return related_events, attributes_tag_set_ids, event_tag_set_ids


def get_score_by_tags(attribute_tags_ids, event_tags_ids, malicious_tag_ids, suspicious_tag_ids):
    """
    Calculates the indicator score by following logic. Indicators of attributes and Events that:
    * have tags which configured as malicious will be scored 3 (i.e malicious).
    * have tags which configured as suspicious will be scored 2 (i.e suspicious).
    * don't have any tags configured as suspicious nor malicious will be scored 0 (i.e unknown).
    In case the same tag appears in both Malicious tag ids and Suspicious tag ids lists the indicator will be scored as
    malicious.
    Attributes tags (both malicious and suspicious) are stronger than events' tags.
    """
    found_tag = None
    is_attribute_tag_malicious = any((found_tag := tag) in attribute_tags_ids for tag in malicious_tag_ids)
    if is_attribute_tag_malicious:
        return Common.DBotScore.BAD, found_tag

    is_attribute_tag_suspicious = any((found_tag := tag) in attribute_tags_ids for tag in suspicious_tag_ids)
    if is_attribute_tag_suspicious:
        return Common.DBotScore.SUSPICIOUS, found_tag

    is_event_tag_malicious = any((found_tag := tag) in event_tags_ids for tag in malicious_tag_ids)
    if is_event_tag_malicious:
        return Common.DBotScore.BAD, found_tag

    is_event_tag_suspicious = any((found_tag := tag) in event_tags_ids for tag in suspicious_tag_ids)
    if is_event_tag_suspicious:
        return Common.DBotScore.SUSPICIOUS, found_tag

    return Common.DBotScore.NONE, None


def get_time_now():
    """
    Returns:
    str: time in year--month--day format
    """
    time_now = time.gmtime(time.time())
    return f'{time_now.tm_year}--{time_now.tm_mon}--{time_now.tm_mday}'


def get_new_event(args):
    """
    Create a new MISP event object and set the event's details.
    """
    event = MISPEvent()
    event.distribution = DISTRIBUTION_NUMBERS[args.get('distribution')]
    threat_level_id_arg = args.get('threat_level_id')
    event.threat_level_id = THREAT_LEVELS_NUMBERS[
        threat_level_id_arg] if threat_level_id_arg in THREAT_LEVELS_NUMBERS else threat_level_id_arg
    analysis_arg = args.get('analysis')
    event.analysis = ANALYSIS_NUMBERS.get(analysis_arg) if analysis_arg in ANALYSIS_NUMBERS else analysis_arg
    event.info = args.get('info') if args.get('info') else 'Event from XSOAR'
    event.date = get_time_now()
    event.published = argToBoolean(args.get('published', 'False'))
    return event


def create_event(demisto_args: dict):
    """Creating event in MISP with the given attribute args"""
    new_event = get_new_event(demisto_args)
    new_event = PYMISP.add_event(new_event, True)

    if isinstance(new_event, dict) and new_event.get('errors'):
        return_error(new_event.get('errors'))

    event_id = get_valid_event_id(new_event.id)
    demisto.debug(f"Create_event command before setting attribute {new_event}")
    add_attribute(event_id=event_id, internal=True, new_event=new_event, demisto_args=demisto_args)
    event = PYMISP.search(eventid=event_id)
    human_readable = f"## MISP create event\nNew event with ID: {event_id} has been successfully created.\n"

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='MISP.Event',
        outputs_key_field='ID',
        outputs=build_events_search_response(copy.deepcopy(event)),
        raw_response=event
    )


def get_valid_event_id(event_id: int):
    if isinstance(event_id, str) and event_id.isdigit():  # type: ignore
        return int(event_id)
    elif not isinstance(event_id, int):
        return_error('Invalid MISP event ID, must be a number')
    return event_id


def get_valid_distribution(distribution: int):
    if not isinstance(distribution, int):
        if isinstance(distribution, str) and distribution.isdigit():  # type: ignore
            return int(distribution)
        elif isinstance(distribution, str) and distribution in DISTRIBUTION_NUMBERS:
            return DISTRIBUTION_NUMBERS[distribution]
        else:
            return_error(
                f"Invalid Distribution. Can be one of the following: {[key for key in DISTRIBUTION_NUMBERS.keys()]}")
    return distribution


def add_attribute(event_id: int = None, internal: bool = False, demisto_args: dict = {}, new_event: MISPEvent = None):
    """Adding attribute to a given MISP event object
    This function can be called as an independence command or as part of another command (create event for example)

    Args:
        event_id (int): Event ID to add attribute to
        internal (bool): if set to True, will not post results to Demisto
        demisto_args (dict): Demisto args
        new_event (MISPEvent): When this function was called from create event command, the attrubite will be added to
        that existing event.
    """
    attributes_args = {
        'id': demisto_args.get('event_id'),  # misp event id
        'type': demisto_args.get('type', 'other'),
        'category': demisto_args.get('category', 'External analysis'),
        'to_ids': argToBoolean(demisto_args.get('to_ids', True)),
        'comment': demisto_args.get('comment'),
        'value': demisto_args.get('value')
    }
    if not event_id:
        event_id = demisto_args.get('event_id')
    event_id = get_valid_event_id(event_id)
    attributes_args.update({'id': event_id}) if event_id else None
    distribution = demisto_args.get('distribution')
    attributes_args.update({'distribution': get_valid_distribution(distribution)}) if distribution else None

    if not new_event:
        response = PYMISP.search(eventid=event_id, pythonify=True)
        if not response:
            return_error(
                f"Error: An event with the given id: {event_id} was not found in MISP. please check it once again")
        new_event = response[0]  # response[0] is MISP event

    new_event.add_attribute(**attributes_args)
    PYMISP.update_event(event=new_event)
    if internal:
        return

    value = attributes_args.get('value')
    updated_event = PYMISP.search(eventid=new_event.id, controller='attributes', value=value)
    human_readable = f"## MISP add attribute\nNew attribute: {value} was added to event id {new_event.id}.\n"
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='MISP.Attribute',
        outputs_key_field='ID',
        outputs=build_attributes_search_response(copy.deepcopy(updated_event)),
        raw_response=updated_event
    )


def generic_reputation_command(demisto_args, reputation_type, dbot_type, malicious_tag_ids, suspicious_tag_ids,
                               reliability):
    reputation_value_list = argToList(demisto_args.get(reputation_type), ',')
    command_results = []
    for value in reputation_value_list:
        command_results.append(
            find_reputation_indicator(value, dbot_type, malicious_tag_ids, suspicious_tag_ids, reliability))
    return command_results


def reputation_value_validation(value, dbot_type):
    if dbot_type == 'FILE':
        # hashFormat will be used only in output
        hash_format = get_hash_type(value)
        if hash_format == 'Unknown':
            return_error('Invalid hash length, enter file hash of format MD5, SHA-1 or SHA-256')
    if dbot_type == 'IP':
        if not is_ip_valid(value):
            return_error(f"Error: The given IP address: {value} is not valid")
    if dbot_type == 'DOMAIN':
        if not re.compile(DOMAIN_REGEX, regexFlags).match(value):
            return_error(f"Error: The given domain: {value} is not valid")
    if dbot_type == 'URL':
        if not re.compile(urlRegex, regexFlags).match(value):
            return_error(f"Error: The given url: {value} is not valid")
    if dbot_type == 'EMAIL':
        if not re.compile(emailRegex, regexFlags).match(value):
            return_error(f"Error: The given email address: {value} is not valid")


def find_reputation_indicator(value, dbot_type, malicious_tag_ids, suspicious_tag_ids, reliability):
    reputation_value_validation(value, dbot_type)
    misp_response = PYMISP.search(value=value, controller='attributes', include_context=True,
                                  include_correlations=True, include_event_tags=True, enforce_warninglist=True,
                                  include_decay_score=True, includeSightings=True)
    indicator_type = DBOT_SCORE_TYPE_MAP[dbot_type]
    is_indicator_found = misp_response and misp_response.get('Attribute')
    if is_indicator_found:
        outputs, score, found_tag = parse_response_reputation_command(copy.deepcopy(misp_response), malicious_tag_ids,
                                                                      suspicious_tag_ids)
        dbot = Common.DBotScore(indicator=value, indicator_type=indicator_type,
                                integration_name=INTEGRATION_NAME,
                                score=score, reliability=reliability, malicious_description="Match found in MISP")
        indicator = get_dbot_indicator(dbot_type, dbot, value)
        events_to_human_readable = get_events_related_to_scored_tag(outputs, found_tag)
        attribute_highlights = reputation_command_to_human_readable(outputs, score, events_to_human_readable)
        readable_output = tableToMarkdown(f'Results found in MISP for value: {value}', attribute_highlights)
        return CommandResults(indicator=indicator,
                              raw_response=misp_response,
                              outputs=outputs,
                              outputs_prefix='MISP.Attribute',
                              outputs_key_field='ID',
                              readable_output=readable_output)

    dbot = Common.DBotScore(indicator=value, indicator_type=indicator_type, integration_name=INTEGRATION_NAME,
                            score=Common.DBotScore.NONE, reliability=reliability,
                            malicious_description="No results were found in MISP")
    indicator = get_dbot_indicator(dbot_type, dbot, value)
    return CommandResults(indicator=indicator,
                          readable_output=f"No attributes found in MISP for value: {value}")


def get_events_related_to_scored_tag(reputation_outputs, found_tag):
    related_events = []
    if found_tag:
        attribute_event = reputation_outputs.get('Event', {})
        event_name = attribute_event.get('Info')
        related_events.extend(get_event_to_tag(attribute_event, found_tag, event_name))  # attribute_event_tags
        related_events.extend(get_event_to_tag(reputation_outputs, found_tag, event_name))  # attribute_tags
        related_events_from_outputs = reputation_outputs.get('RelatedAttribute')
        if related_events_from_outputs:
            for event in related_events_from_outputs:
                event_object = event.get('Event')
                event_name = event_object.get('Info')
                related_events.extend(get_event_to_tag(event_object, found_tag, event_name))  # attribute_event_tags
                related_events.extend(get_event_to_tag(event, found_tag, event_name))  # event_tags
    return remove_duplicated_related_events(related_events)


def remove_duplicated_related_events(related_events):
    related_events_no_duplicates = []
    for i in range(len(related_events)):
        if related_events[i] not in related_events[i + 1:]:
            related_events_no_duplicates.append(related_events[i])
    return related_events_no_duplicates


def get_event_to_tag(data_dict, found_tag, event_name):
    related_events = []
    for tag in data_dict.get('Tag', []):
        if tag.get('ID') == found_tag:
            event_id = data_dict.get('EventID') if data_dict.get('EventID') else data_dict.get('ID')
            tag_name = tag.get('Name')
            related_events.append({'Event_ID': event_id, 'Event_Name': event_name,
                                   'Tag_Name': tag_name, 'Tag_ID': tag.get('ID')})
    return related_events


def get_dbot_indicator(dbot_type, dbot_score, value):
    if dbot_type == "FILE":
        return Common.File(dbot_score=dbot_score, name=value)
    if dbot_type == "IP":
        return Common.IP(ip=value, dbot_score=dbot_score)
    if dbot_type == "DOMAIN":
        return Common.Domain(domain=value, dbot_score=dbot_score)
    if dbot_type == "EMAIL":
        return Common.EMAIL(address=value, dbot_score=dbot_score)
    if dbot_type == "URL":
        return Common.URL(url=value, dbot_score=dbot_score)


def build_misp_complex_filter(demisto_query: str) -> str:
    """
    Args:
        demisto_query: complex query contains saved words: 'AND:', 'OR:' and 'NOT:'
            using ',' as delimiter for parameters and ';' as delimiter for operators.
            using the operators is optional.
            if 'demisto_query' does not contains any of the complex operators the original
            input will be returned

    Returns:
        str: dictionary created for misp to perform complex query
        or if no complex query found returns the original input

    Example:
        demisto_query should look like:
            example 1: "AND:param1,param2;OR:param3;NOT:param4,param5"
            example 2: "NOT:param3,param5"
            example 3 (simple syntax): "param1,param2"
    """

    regex_and = r'(AND:)([^\;]+)(;)?'
    regex_or = r'(OR:)([^\;]+)(;)?'
    regex_not = r'(NOT:)([^\;]+)(;)?'
    misp_query_params = dict()
    is_complex_search = False
    match_and = re.search(regex_and, demisto_query, re.MULTILINE)
    match_or = re.search(regex_or, demisto_query, re.MULTILINE)
    match_not = re.search(regex_not, demisto_query, re.MULTILINE)

    if match_and is not None:
        misp_query_params['and_parameters'] = match_and.group(2).split(',')
        is_complex_search = True

    if match_or is not None:
        misp_query_params['or_parameters'] = match_or.group(2).split(',')
        is_complex_search = True

    if match_not is not None:
        misp_query_params['not_parameters'] = match_not.group(2).split(',')
        is_complex_search = True

    if is_complex_search:
        misp_complex_query = PYMISP.build_complex_query(**misp_query_params)
        return misp_complex_query

    return demisto_query


def prepare_args_to_search():
    d_args = demisto.args()
    # List of all applicable search arguments
    args = dict()
    # Create dict to pass into the search
    for arg in MISP_SEARCH_ARGUMENTS:
        if arg in d_args:
            args[arg] = d_args[arg]
    # Replacing keys and values from Demisto to Misp's keys
    if 'type' in args:
        args['type_attribute'] = args.pop('type')
    # search function 'to_ids' parameter gets 0 or 1 instead of bool.
    if 'to_ids' in args:
        args['to_ids'] = 1 if d_args.get('to_ids') in ('true', '1', 1) else 0
    if 'from' in args:
        args['from_date'] = args.pop('from')
    if 'to' in args:
        args['to_date'] = args.pop('to')
    if 'event_id' in args:
        args['eventid'] = argToList(args.pop('event_id'))
    if 'last' in args:
        args['publish_timestamp'] = args.pop('last')
    if 'include_decay_score' in args:
        args['include_decay_score'] = 1 if d_args.get('include_decay_score') in ('true', '1', 1) else 0
    if 'include_sightings' in args:
        args['include_sightings'] = 1 if d_args.get('include_sightings') in ('true', '1', 1) else 0
    if 'include_correlations' in args:
        args['include_correlations'] = 1 if d_args.get('include_correlations') in ('true', '1', 1) else 0
    # search function 'enforceWarninglist' parameter gets 0 or 1 instead of bool.
    if 'enforceWarninglist' in args:
        args['enforceWarninglist'] = 1 if d_args.get('enforceWarninglist') in ('true', '1', 1) else 0
    if 'limit' not in args:
        args['limit'] = '50'
    # build MISP complex filter
    if 'tags' in args:
        args['tags'] = build_misp_complex_filter(args['tags'])
    demisto.debug(f"args for request search command are {args}")
    return args


def build_attributes_search_response(response_object: Union[dict, requests.Response],
                                     include_correlations=False) -> dict:
    """
    Convert the response of attribute search returned from MIPS to the context output format.
    """
    if include_correlations:
        # if user want to get back the related attributes only
        ATTRIBUTE_FIELDS.append('RelatedAttribute')

    if isinstance(response_object, str):
        response_object = json.loads(json.dumps(response_object))
    attributes = response_object.get('Attribute')
    for i in range(len(attributes)):
        attributes[i] = {key: attributes[i].get(key) for key in ATTRIBUTE_FIELDS if key in attributes[i]}
        # Build Galaxy
        if attributes[i].get('Galaxy'):
            attributes[i]['Galaxy'] = [
                {
                    'name': star.get('name'),
                    'type': star.get('type'),
                    'description': star.get('description')
                } for star in attributes[i]['Galaxy']
            ]

        # Build Tag
        if attributes[i].get('Tag'):
            attributes[i]['Tag'] = [
                {'Name': tag.get('name'),
                 'is_galaxy': tag.get('is_galaxy')
                 } for tag in attributes[i].get('Tag')
            ]

        if attributes[i].get('Sighting'):
            attributes[i]['Sighting'] = [
                {'type': sighting.get('type')
                 } for sighting in attributes[i].get('Sighting')
            ]

    attributes = replace_keys(attributes)
    return attributes


def build_attributes_search_response_only_values(response_object: Union[dict, requests.Response]) -> list:
    """returns list of attributes' values that match the search query"""
    if isinstance(response_object, str):
        response_object = json.loads(json.dumps(response_object))
    attributes = response_object.get('Attribute')
    return [attribute.get('value') for attribute in attributes]


def pagination_args_validation(page, limit):
    try:
        page = int(page)
        limit = int(limit)
    except ValueError:
        raise DemistoException("page and limit should be numbers")
    return page, limit


def attribute_response_to_markdown_table(response: dict):
    attribute_highlights = []
    for attribute in response:
        event = attribute.get('Event', {})
        attribute_tags = [tag.get('Name') for tag in attribute.get('Tag')] if attribute.get(
            'Tag') else None
        attribute_sightings = [SIGHTING_FROM_TYPE_MAP[sighting.get('Type')] for sighting in
                               attribute.get('Sighting')] if attribute.get('Sighting') else None
        attribute_highlights.append({
            'Attribute ID': attribute.get('ID'),
            'Event ID': attribute.get('EventID'),
            'Attribute Category': attribute.get('Category'),
            'Attribute Type': attribute.get('Type'),
            'Attribute Comment': attribute.get('Comment'),
            'Attribute Value': attribute.get('Value'),
            'Attribute Tags': attribute_tags,
            'Attribute Sightings': attribute_sightings,
            'To IDs': attribute.get('ToIDs'),
            'Timestamp': convert_timestamp(attribute.get('Timestamp')),
            'Event Info': event.get('Info'),
            'Event Organisation ID': event.get('OrganisationID'),
            'Event Distribution': event.get('Distribution'),
            'Event UUID': event.get('UUID')
        })
    return attribute_highlights


def search_attributes(demisto_args: dict) -> CommandResults:
    """
    Execute a MIPS search using the 'attributes' controller.
    """
    args = prepare_args_to_search()
    # Set the controller to attributes to search for attributes and not events
    args['controller'] = 'attributes'
    response = PYMISP.search(**args)
    return_only_values = argToBoolean(demisto_args.get('compact', False))
    include_correlations = argToBoolean(demisto_args.get('include_correlations', False))
    limit = demisto_args.get('limit', 50)
    page = demisto_args.get('page')
    if page:
        pagination_args_validation(page, limit)

    if response:
        if return_only_values:
            response_for_context = build_attributes_search_response_only_values(response)
            number_of_results = len(response_for_context)
            md = tableToMarkdown(f"MISP search-attributes returned {number_of_results} attributes",
                                 response_for_context[:number_of_results], ["Value"])
        else:
            response_for_context = build_attributes_search_response(copy.deepcopy(response), include_correlations)
            attribute_highlights = attribute_response_to_markdown_table(response_for_context)
            md = tableToMarkdown(f"MISP search-attributes returned {len(response_for_context)} attributes",
                                 attribute_highlights, removeNull=True)
        if page:
            md += f"Current page number: {page}\n Page size: {limit}"

        return CommandResults(
            raw_response=response,
            readable_output=md,
            outputs=response_for_context,
            outputs_prefix="MISP.Attribute",
            outputs_key_field="ID"
        )
    else:
        return CommandResults(readable_output=f"No attributes found in MISP for the given filters: {args}")


def build_events_search_response(response_object: Union[dict, requests.Response]) -> dict:
    """
    Convert the response of event search returned from MIPS to the context output format.
    please note: attributes are excluded from search-events output as the information is too big. User can use the
    command search-attributes in order to get the information about the attributes.
    """
    if isinstance(response_object, str):
        response_object = json.loads(json.dumps(response_object))
    events = [event.get('Event') for event in response_object]
    for i in range(0, len(events)):
        # Filter object from keys in event_args
        events[i] = {key: events[i].get(key) for key in EVENT_FIELDS if key in events[i]}
        # Remove 'Event' keyword from 'RelatedEvent'
        if events[i].get('RelatedEvent'):
            events[i]['RelatedEvent'] = [r_event.get('Event') for r_event in events[i].get('RelatedEvent')]
            # Get only IDs from related event
            events[i]['RelatedEvent'] = [
                {
                    'id': r_event.get('id')
                } for r_event in events[i].get('RelatedEvent')
            ]
        # Build Galaxy
        if events[i].get('Galaxy'):
            events[i]['Galaxy'] = [
                {
                    'name': star.get('name'),
                    'type': star.get('type'),
                    'description': star.get('description')
                } for star in events[i]['Galaxy']
            ]
        # Build tag
        if events[i].get('Tag'):
            events[i]['Tag'] = [
                {'Name': tag.get('name'),
                 'is_galaxy': tag.get('is_galaxy')
                 } for tag in events[i].get('Tag')
            ]

        # Build Object
        if events[i].get('Object'):
            events[i]['Object'] = [
                {
                    'name': event_object.get('name'),
                    'uuid': event_object.get('uuid'),
                    'description': event_object.get('description'),
                    'id': event_object.get('id')
                } for event_object in events[i]['Object']
            ]
    events = replace_keys(events)  # type: ignore
    return events  # type: ignore


def event_response_to_markdown_table(response: dict):
    event_highlights = []
    for event in response:
        event_tags = [tag.get('Name') for tag in event.get('Tag')] if event.get('Tag') else None
        event_galaxies = [galaxy.get('Name') for galaxy in event.get('Galaxy')] if event.get('Galaxy') else None
        event_objects = [event_object.get('ID') for event_object in event.get('Object')] if event.get(
            'Object') else None
        event_highlights.append({
            'Event ID': event.get('ID'),
            'Event Tags': event_tags,
            'Event Galaxies': event_galaxies,
            'Event Objects': event_objects,
            'Publish Timestamp': convert_timestamp(event.get('PublishTimestamp')),
            'Event Info': event.get('Info'),
            'Event Org ID': event.get('OrganisationID'),
            'Event Orgc ID': event.get('OwnerOrganisation.ID'),
            'Event Distribution': event.get('Distribution'),
            'Event UUID': event.get('UUID'),

        })
    return event_highlights


def search_events(demisto_args) -> CommandResults:
    """
    Execute a MIPS search using the 'event' controller.
    """
    args = prepare_args_to_search()
    # Set the controller to events to search for events by the given args
    args['controller'] = 'events'
    response = PYMISP.search(**args)
    page = demisto_args.get('page')
    limit = demisto_args.get('limit', 50)

    if response:
        response_for_context = build_events_search_response(copy.deepcopy(response))
        event_highlights = event_response_to_markdown_table(response_for_context)
        md = tableToMarkdown(f"MISP search-events returned {len(response_for_context)} events",
                             event_highlights, removeNull=True)
        if page:
            md += f"Current page number: {page}\n Page size: {limit} "

        return CommandResults(
            raw_response=response,
            readable_output=md,
            outputs=response_for_context,
            outputs_prefix="MISP.Event",
            outputs_key_field="ID"
        )
    else:
        return CommandResults(readable_output=f"No events found in MISP for the given filters: {args}")


def delete_event(demisto_args: dict):
    """
    Gets an event id and deletes it.
    """
    event_id = demisto_args.get('event_id')
    event = PYMISP.delete_event(event_id)
    if 'errors' in event:
        return_error(f'Event ID: {event_id} has not found in MISP: \nError message: {event}')
    else:
        human_readable = f'Event {event_id} has been deleted'
        return CommandResults(readable_output=human_readable, raw_response=event)


def add_tag(demisto_args: dict, is_attribute=False):
    """
    Function will add tag to given UUID of event or attribute.
    is_attribute (bool): if the given UUID is an attribute's one. Otherwise it's event's.
    """
    uuid = demisto_args.get('uuid')
    tag = demisto_args.get('tag')
    PYMISP.tag(uuid, tag)  # add the tag
    if is_attribute:
        response = PYMISP.search(uuid=uuid, controller='attributes')
        human_readable = f'Tag {tag} has been successfully added to attribute {uuid}'
        return CommandResults(
            readable_output=human_readable,
            outputs_prefix='MISP.Attribute',
            outputs_key_field='ID',
            outputs=build_attributes_search_response(response),
            raw_response=response
        )

    # event's uuid
    response = PYMISP.search(uuid=uuid)
    human_readable = f'Tag {tag} has been successfully added to event {uuid}'
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='MISP.Event',
        outputs_key_field='ID',
        outputs=build_events_search_response(response),
        raw_response=response
    )


def remove_tag(demisto_args: dict, is_attribute=False):
    """
    Function will remove tag to given UUID of event or attribute.
    is_attribute (bool): if the given UUID is an attribute's one. Otherwise it's event's.
    """
    uuid = demisto_args.get('uuid')
    tag = demisto_args.get('tag')

    PYMISP.untag(uuid, tag)
    if is_attribute:
        response = PYMISP.search(uuid=uuid, controller='attributes')
        human_readable = f'Tag {tag} has been successfully removed from the attribute {uuid}'
        return CommandResults(
            readable_output=human_readable,
            outputs_prefix='MISP.Attribute',
            outputs_key_field='ID',
            outputs=build_attributes_search_response(response),
            raw_response=response
        )

    # event's uuid
    response = PYMISP.search(uuid=uuid)
    human_readable = f'Tag {tag} has been successfully removed from the event {uuid}'
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='MISP.Event',
        outputs_key_field='ID',
        outputs=build_events_search_response(response),
        raw_response=response
    )


def add_sighting(demisto_args: dict):
    """Adds sighting to MISP attribute
    """
    attribute_id = demisto_args.get('id')
    attribute_uuid = demisto_args.get('uuid')
    sighting_type = demisto_args['type']  # mandatory arg
    att_id = attribute_id or attribute_uuid
    if not att_id:
        return_error('ID or UUID not specified')

    sighting_args = {
        'id': attribute_id,
        'uuid': attribute_uuid,
        'type': SIGHTING_TO_TYPE_MAP[sighting_type]
    }
    sigh_obj = MISPSighting()
    sigh_obj.from_dict(**sighting_args)
    PYMISP.add_sighting(sigh_obj, att_id)

    human_readable = f'Sighting \'{sighting_type}\' has been successfully added to attribute {att_id}'
    return CommandResults(readable_output=human_readable)


def test(malicious_tag_ids, suspicious_tag_ids):
    """
    Test module.
    """
    is_tag_list_valid(malicious_tag_ids)
    is_tag_list_valid(suspicious_tag_ids)
    response = PYMISP._prepare_request('GET', 'servers/getPyMISPVersion.json')
    if PYMISP._check_json_response(response):
        return 'ok'
    else:
        return_error('MISP has not connected.')


def add_events_from_feed(demisto_args: dict, use_ssl: bool, proxies: dict):
    """Gets an OSINT feed from url and publishing them to MISP
    urls with feeds for example: `https://www.misp-project.org/feeds/`
    feed format must be MISP.
    """
    headers = {'Accept': 'application/json'}
    url = demisto_args.get('feed')  # type: str
    url = url[:-1] if url.endswith('/') else url
    if PREDEFINED_FEEDS.get(url):
        url = PREDEFINED_FEEDS[url].get('url')  # type: ignore
    limit = demisto_args.get('limit')  # type: str
    limit_int = int(limit) if limit.isdigit() else 0

    osint_url = f'{url}/manifest.json'
    not_added_counter = 0
    try:
        uri_list = requests.get(osint_url, verify=use_ssl, headers=headers, proxies=proxies).json()
        events_numbers = list()  # type: List[Dict[str, int]]
        for num, uri in enumerate(uri_list, 1):
            req = requests.get(f'{url}/{uri}.json', verify=use_ssl, headers=headers, proxies=proxies).json()
            e = MISPEvent()
            e.load(req)
            event = PYMISP.add_event(e)
            event_data = event.get('Event')
            if event_data and 'id' in event_data:
                events_numbers.append({'ID': event_data['id']})
            else:
                not_added_counter += 1
            # If limit exists
            if limit_int == num:
                break

        human_readable = tableToMarkdown(f'Total of {len(events_numbers)} events was added to MISP.', events_numbers)
        if not_added_counter:
            human_readable = f'{human_readable}\n' \
                             f'{not_added_counter} events were not added. Might already been added earlier.'

        return CommandResults(
            readable_output=human_readable,
            outputs_prefix='MISP.Event',
            outputs_key_field='ID',
            outputs=events_numbers,
        )

    except ValueError as e:
        return_error(f'URL [{url}] is not a valid MISP feed. error: {e}')


def add_object(event_id: str, obj: MISPObject):
    """Sending object to MISP and returning outputs

    Args:
        obj: object to add to MISP
        event_id: ID of event
    """
    response = PYMISP.add_object(event_id, misp_object=obj)
    if 'errors' in response:
        return_error(f'Error in `{demisto.command()}` command: {response}')
    for ref in obj.ObjectReference:
        response = PYMISP.add_object_reference(ref)
    formatted_response = replace_keys(response)
    formatted_response.update({"ID": event_id})

    human_readable = f'Object has been added to MISP event ID {event_id}'
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='MISP.Event',
        outputs_key_field='ID',
        outputs=formatted_response,
    )


def add_file_object(demisto_args: dict = {}):
    entry_id = demisto_args.get('entry_id')
    event_id = demisto_args.get('event_id')
    file_path = demisto.getFilePath(entry_id).get('path')
    obj = FileObject(file_path)
    return add_object(event_id, obj)


def add_domain_object(demisto_args: dict = {}):
    """Adds a domain object to MISP
    domain-ip description: https://www.misp-project.org/objects.html#_domain_ip
    """
    text = demisto_args.get('text')
    event_id = demisto_args.get('event_id')
    domain = demisto_args.get('name')
    obj = MISPObject('domain-ip')
    ips = argToList(demisto_args.get('dns'))
    for ip in ips:
        obj.add_attribute('ip', value=ip)
    obj.add_attribute('domain', value=domain)
    if text:
        obj.add_attribute('text', value=text)
    return add_object(event_id, obj)


def add_url_object(demisto_args: dict = {}):
    """Building url object in MISP scheme
    Scheme described https://www.misp-project.org/objects.html#_url
    """

    url_args = [
        'text',
        'last_seen',
        'first_seen'
    ]
    event_id = demisto_args.get('event_id')
    url = demisto_args.get('url')
    url_parse = urlparse(url)
    url_obj = [{'url': url}]
    url_obj.append({'scheme': url_parse.scheme}) if url_parse.scheme else None
    url_obj.append({'resource_path': url_parse.path}) if url_parse.path else None
    url_obj.append({'query_string': url_parse.query}) if url_parse.query else None
    url_obj.append({'domain': url_parse.netloc}) if url_parse.netloc else None
    url_obj.append({'fragment': url_parse.fragment}) if url_parse.fragment else None
    url_obj.append({'port': url_parse.port}) if url_parse.port else None
    url_obj.append(
        {'credential': (url_parse.username, url_parse.password)}) if url_parse.username and url_parse.password else None
    url_obj.extend(convert_arg_to_misp_args(demisto_args, url_args))

    g_object = build_generic_object('url', url_obj)
    demisto.debug(f"in add_url_object, g_object is: {g_object}")
    return add_object(event_id, g_object)


def add_generic_object_command(demisto_args: dict = {}):
    event_id = demisto_args.get('event_id')
    template = demisto_args.get('template')
    attributes = demisto_args.get('attributes').replace("'", '"')
    try:
        args = json.loads(attributes)
        if not isinstance(args, list):
            args = build_list_from_dict(args)
        obj = build_generic_object(template, args)
        return add_object(event_id, obj)
    except ValueError as e:
        return_error(f'`attribute` parameter could not be decoded, may not a valid JSON\nattribute: {attributes}',
                     str(e))


def convert_arg_to_misp_args(demisto_args, args_names):
    return [{arg.replace('_', '-'): demisto_args.get(arg)} for arg in args_names if demisto_args.get(arg)]


def add_ip_object(demisto_args: dict = {}):
    event_id = demisto_args.get('event_id')
    args = [
        'dst_port',
        'src_port',
        'domain',
        'hostname',
        'ip_src',
        'ip_dst'
    ]
    # converting args to MISP's arguments types
    misp_attributes_args = convert_arg_to_misp_args(demisto_args, args)
    ips = argToList(demisto_args.get('ip'))
    for ip in ips:
        misp_attributes_args.append({'ip': ip})
    if misp_attributes_args:
        non_req_args = [
            'first_seen',
            'last_seen',
        ]
        misp_attributes_args.extend(convert_arg_to_misp_args(demisto_args, non_req_args))
        misp_attributes_args.append({'text': demisto_args.get('comment')}) if demisto_args.get('comment') else None
        obj = build_generic_object('ip-port', misp_attributes_args)
        return add_object(event_id, obj)
    else:
        return_error(f'None of required arguments presents. command {demisto.command()} requires one of {args}')


def handle_tag_duplication_ids(malicious_tag_ids, suspicious_tag_ids):
    common_ids = set(malicious_tag_ids) & set(suspicious_tag_ids)
    for duplicate_id in common_ids:
        suspicious_tag_ids.remove(duplicate_id)
    return malicious_tag_ids, suspicious_tag_ids


def is_tag_list_valid(tag_ids):
    """checks if all the tag ids are valid"""
    for tag in tag_ids:
        try:
            int(tag)
        except ValueError:
            raise DemistoException(f"Tag id has to be an integer, please change the given: '{tag}' id.")


def main():
    params = demisto.params()
    malicious_tag_ids = argToList(params.get('malicious_tag_ids'))
    suspicious_tag_ids = argToList(params.get('suspicious_tag_ids'))
    reliability = params.get('integrationReliability', 'B - Usually reliable')
    if DBotScoreReliability.is_valid_type(reliability):
        reliability = DBotScoreReliability.get_dbot_score_reliability_from_str(reliability)
    else:
        Exception("MISP V3 error: Please provide a valid value for the Source Reliability parameter")

    command = demisto.command()
    demisto.debug(f'MISP V3: command is {command}')
    args = demisto.args()

    try:
        malicious_tag_ids, suspicious_tag_ids = handle_tag_duplication_ids(malicious_tag_ids, suspicious_tag_ids)
        if command == 'test-module':
            return_results(test(malicious_tag_ids=malicious_tag_ids, suspicious_tag_ids=suspicious_tag_ids))
        elif command == 'misp-create-event':
            return_results(create_event(args))
        elif command == 'misp-add-attribute':
            return_results(add_attribute(demisto_args=args))
        elif command == 'misp-search-events':
            return_results(search_events(args))
        elif command == 'misp-search-attributes':
            return_results(search_attributes(args))
        elif command == 'misp-delete-event':
            return_results(delete_event(args))
        elif command == 'misp-add-sighting':
            return_results(add_sighting(args))
        elif command == 'misp-add-tag-to-event':
            return_results(add_tag(args))
        elif command == 'misp-add-tag-to-attribute':
            return_results(add_tag(demisto_args=args, is_attribute=True))
        elif command == 'misp-remove-tag-from-event':
            return_results(remove_tag(args))
        elif command == 'misp-remove-tag-from-attribute':
            return_results(remove_tag(demisto_args=args, is_attribute=True))
        elif command == 'misp-add-events-from-feed':
            return_results(add_events_from_feed(demisto_args=args, use_ssl=verify, proxies=proxies))
        elif command == 'file':
            return_results(
                generic_reputation_command(args, 'file', 'FILE', malicious_tag_ids, suspicious_tag_ids, reliability))
        elif command == 'url':
            return_results(
                generic_reputation_command(args, 'url', 'URL', malicious_tag_ids, suspicious_tag_ids, reliability))
        elif command == 'ip':
            return_results(
                generic_reputation_command(args, 'ip', 'IP', malicious_tag_ids, suspicious_tag_ids, reliability))
        elif command == 'domain':
            return_results(
                generic_reputation_command(args, 'domain', 'DOMAIN', malicious_tag_ids, suspicious_tag_ids,
                                           reliability))
        elif command == 'email':
            return_results(generic_reputation_command(args, 'email', 'EMAIL', malicious_tag_ids, suspicious_tag_ids,
                                                      reliability))
        elif command == 'misp-add-file-object':
            return_results(add_file_object(args))
        elif command == 'misp-add-domain-object':
            return_results(add_domain_object(args))
        elif command == 'misp-add-url-object':
            return_results(add_url_object(args))
        elif command == 'misp-add-ip-object':
            return_results(add_ip_object(args))
        elif command == 'misp-add-object':
            return_results(add_generic_object_command(args))
    except PyMISPError as e:
        return_error(e.message)
    except Exception as e:
        return_error(str(e))


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
