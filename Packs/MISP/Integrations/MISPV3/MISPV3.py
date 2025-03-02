import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import urllib3
import copy

from urllib.parse import urlparse
from pymisp import ExpandedPyMISP, PyMISPError, MISPObject, MISPSighting, MISPEvent, MISPAttribute, MISPUser, MISPServerError
from pymisp.tools import GenericObjectGenerator, EMailObject
from pymisp.tools import FileObject
from base64 import b64decode
import tempfile

logging.getLogger("pymisp").setLevel(logging.CRITICAL)


class TempFile:
    def __init__(self, data):
        _, self.path = tempfile.mkstemp()
        with open(self.path, 'w') as temp_file:
            temp_file.write(data)

    def __del__(self):
        import os
        os.remove(self.path)


def handle_connection_errors(error):
    if "SSLError" in error:
        return_error('Unable to connect to MISP because of a SSLCertVerificationError, '
                     'Please try to use the Trust any certificate option.')
    if "NewConnectionError" in error:
        return_error('Unable to connect to MISP because of a NewConnectionError, '
                     'Please make sure your MISP server url is correct.')
    if "Please make sure the API key and the URL are correct" in error:
        return_error('Unable to connect to MISP, '
                     'Please make sure the API key is correct.')
    return_error(error)


def warn(*args):
    """
    Do nothing with warnings
    """


# Disable requests warnings
urllib3.disable_warnings()

# Disable python warnings
warnings.warn = warn

''' GLOBALS/PARAMS '''
params = demisto.params()
if not params.get('credentials') or not (MISP_API_KEY := params.get('credentials', {}).get('password')):
    raise DemistoException('Missing API Key. Fill in a valid key in the integration configuration.')
MISP_URL = params.get('url')
TO_IDS = params.get('check_to_ids')
ALLOWED_ORGS = argToList(params.get('allowed_orgs'), ',')
VERIFY = not params.get('insecure')
CERTIFICATE = replace_spaces_in_credential(params.get('certificate', {}).get('identifier'))
PRIVATE_KEY = replace_spaces_in_credential(params.get('certificate', {}).get('password'))
cert = TempFile(CERTIFICATE) if CERTIFICATE else None
key = TempFile(PRIVATE_KEY) if PRIVATE_KEY else None
misp_client_cert = (cert.path, key.path) if cert and key else None

PROXIES = handle_proxy()  # type: ignore
try:
    PYMISP = ExpandedPyMISP(url=MISP_URL, key=MISP_API_KEY, ssl=VERIFY, proxies=PROXIES, cert=misp_client_cert)
except PyMISPError as e:
    handle_connection_errors(e.message)

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

THREAT_LEVELS_TO_ID = {
    'High': 1,
    'Medium': 2,
    'Low': 3,
    'Unknown': 4
}

MISP_ENTITIES_TO_CONTEXT_DATA = {
    'deleted': 'Deleted',
    'category': 'Category',
    'comment': 'Comment',
    'uuid': 'UUID',
    'sharing_group_id': 'SharingGroupID',
    'timestamp': 'LastChanged',
    'to_ids': 'ToIDs',
    'value': 'Value',
    'event_id': 'EventID',
    'ShadowAttribute': 'ShadowAttribute',
    'disable_correlation': 'DisableCorrelation',
    'distribution': 'Distribution',
    'type': 'Type',
    'id': 'ID',
    'date': 'CreationDate',
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
    'org_id': 'OrganizationID',
    'Org': 'Organization',
    'Orgc': 'OwnerOrganization',
    'orgc_uuid': 'OwnerOrganization.UUID',
    'orgc_id': 'OwnerOrganization.ID',
    'orgc_name': 'OwnerOrganization.Name',
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
    'last_seen': 'last_seen',
    'provider': 'Provider',
    'source_format': 'SourceFormat',
    'url': 'URL',
    'event_uuids': 'EventUUIDS',
}

MISP_ANALYSIS_TO_IDS = {
    'initial': 0,
    'ongoing': 1,
    'completed': 2
}

MISP_DISTRIBUTION_TO_IDS = {
    'Your_organization_only': 0,
    'This_community_only': 1,
    'Connected_communities': 2,
    'All_communities': 3,
    'Sharing_group': 4,
    'Inherit_event': 5
}

SIGHTING_TYPE_NAME_TO_ID = {
    'sighting': 0,
    'false_positive': 1,
    'expiration': 2
}

SIGHTING_TYPE_ID_TO_NAME = {
    '0': 'sighting',
    '1': 'false_positive',
    '2': 'expiration'
}

INDICATOR_TYPE_TO_DBOT_SCORE = {
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
    'include_feed_correlations',
    'eventinfo',
    'with_attachments'
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
    'Object',
    'Feed',
    'Attribute',
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


def extract_error(error: list) -> list[dict]:
    """
    Extracting errors raised by PYMISP into readable response, for more information and examples
    please see UT: test_extract_error.

    Args:
        error: list of responses from error section

    Returns:
        List[Dict[str, any]]: filtered response
    """
    return [{
        'code': err[0],
        'message': err[1].get('message'),
        'errors': err[1].get('errors')
    } for err in error]


def dict_to_generic_object_format(args: dict) -> list[dict]:
    """
    Converts args dict into a list, please see GenericObjectGenerator Class in Pymisp.
    Args:
        args: dictionary describes MISP object

    Returns:
        list: list containing dicts that GenericObjectGenerator can take.

    Examples:
        >>> {'ip': '8.8.8.8', 'domain': 'google.com'}
        [{'ip': '8.8.8.8'}, {'domain': 'google.com'}]
    """
    return [{k: v} for k, v in args.items()]


def build_generic_object(template_name: str, args: list[dict]) -> GenericObjectGenerator:
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


def build_custom_object(template_name: str, args: list[dict]):
    obj = PYMISP.object_templates()
    for entry in obj:
        if str(entry.get('ObjectTemplate', {}).get('name')).lower() == template_name:  # type: ignore[union-attr]

            custom_obj = PYMISP.get_raw_object_template(template_name)

            if not os.path.exists(f'/tmp/{template_name}'):
                os.mkdir(f'/tmp/{template_name}')
            open(f'/tmp/{template_name}/definition.json', 'w').write(json.dumps(custom_obj))

            misp_object = MISPObject(name=template_name, misp_objects_path_custom='/tmp')

            for arg in args:
                for key, value in arg.items():
                    misp_object.add_attribute(key, value)

            return misp_object

    return False


def misp_convert_timestamp_to_date_string(timestamp: str | int) -> str:
    """
    Gets a timestamp from MISP response (1546713469) and converts it to human readable format
    """
    return datetime.utcfromtimestamp(int(timestamp)).strftime('%Y-%m-%dT%H:%M:%SZ') if timestamp else ""


def replace_keys_from_misp_to_context_data(obj_to_build: dict | list | str) -> dict | list | str:
    """
    Replacing keys from MISP's format to Demisto's (as appear in ENTITIESDICT)

    Args:
        obj_to_build (Union[dict, list, str]): object to replace keys in

    Returns:
        Union[dict, list, str]: same object type that got in
    """
    if isinstance(obj_to_build, list):
        return [replace_keys_from_misp_to_context_data(item) for item in obj_to_build]
    if isinstance(obj_to_build, dict):
        return {
            (MISP_ENTITIES_TO_CONTEXT_DATA[key] if key in MISP_ENTITIES_TO_CONTEXT_DATA else key):
                replace_keys_from_misp_to_context_data(value) for key, value in obj_to_build.items()
        }
    return obj_to_build


def reputation_command_to_human_readable(outputs, score, events_to_human_readable):
    found_tag_id, found_tag_name = "", ""
    for event in events_to_human_readable:
        # removing those fields as they are shared by the events
        found_tag_id = event.pop('Tag_ID')
        found_tag_name = event.pop('Tag_Name')
    return {
        'Attribute Type': outputs[0].get('Type'),
        'Dbot Score': score,
        'Attribute Value': outputs[0].get('Value'),
        'Attribute Category': outputs[0].get('Category'),
        'Timestamp': outputs[0].get('Timestamp'),
        'Events with the scored tag': events_to_human_readable,
        'Scored Tag ID': found_tag_id,
        'Scored Tag Name': found_tag_name,
    }


def limit_tag_output_to_id_and_name(attribute_dict, is_event_level):
    """
    As tag list can be full of in unnecessary data, we want to limit this list to include only the ID and Name fields.
    In addition, returns set of the found tag ids.

    Some tags have a field called inherited. When it is set to 1 it says that it is an event's tag.
    Otherwise (if it is set to 0 or not exists) it says that it is an attribute's tag.
    If the data is event's (is_event_level = true) we would like to add to tag_set_ids all the tags
    (event ones and the event's attribute tags ones as it is part of the event scope).
    If the data is attribute's (is_event_level = false), and the tag is only related to an attribute
    we would like to add it to tag_set_ids. In any other case, we won't add the tag.

    Args:
        attribute_dict (dict): The dictionary that includes the tag list.
        is_event_level (bool): Whether the attribute_dict was received from an event object,
        meaning the tags are event's ones. Otherwise, the data is attribute's (attribute tags).
    """
    output = []
    tag_set_ids = set()
    tags_list = attribute_dict.get('Tag', [])
    for tag in tags_list:
        is_event_tag = tag.get('inherited', 0)  # field doesn't exist when this is an attribute level, default is '0'
        tag_id = tag.get('id')
        if is_event_level:
            tag_set_ids.add(tag_id)
        else:  # attribute level
            if not is_event_tag:
                tag_set_ids.add(tag_id)
        output.append({'ID': tag_id, 'Name': tag.get('name')})
    return output, tag_set_ids


def parse_response_reputation_command(
    misp_response: dict,
    malicious_tag_ids: set,
    suspicious_tag_ids: set,
    benign_tag_ids: set,
    attributes_limit: int
):
    """
    After getting all the attributes which match the required indicator value, this function parses the response.
    This function goes over all the attributes that found (after limit the attributes amount to the given limit)
    and by sub-functions calculated the score of the indicator.
    For the context data outputs, for every attribute we remove the "Related Attribute" list and limits the tags and
    galaxies lists. Eventually, the outputs will be a list of attributes along with their events objects.
    Note: When limits the attributes amount, we sort the attributes list by the event ids as the greater event ids are
    the newer ones.

    Returns:
        response (dict): The parsed outputs to context data (array of attributes).
        score: the indicator score
        found_tag: the tag (id) which made the indicator to get that score
        found_related_events (dict): contains info (name, id, threat level id) about all the events that include
        the indicator

    Please see an example for a response in test_data/reputation_command_response.json
    Please see an example for a parsed output in test_data/reputation_command_outputs.json
        """
    response = copy.deepcopy(misp_response)
    attributes_list = response.get('Attribute')
    if not attributes_list:
        return None
    attributes_list = sorted(attributes_list,
                             key=lambda attribute_item: attribute_item['event_id'], reverse=True)[:attributes_limit]
    found_related_events, attributes_tag_ids, event_tag_ids = prepare_attributes_array_to_context_data(attributes_list)
    attribute_in_event_with_bad_threat_level = found_event_with_bad_threat_level_id(found_related_events)
    score, found_tag = get_score(attribute_tags_ids=attributes_tag_ids, event_tags_ids=event_tag_ids,
                                 malicious_tag_ids=malicious_tag_ids, suspicious_tag_ids=suspicious_tag_ids,
                                 benign_tag_ids=benign_tag_ids,
                                 is_attribute_in_event_with_bad_threat_level=attribute_in_event_with_bad_threat_level)
    formatted_response = replace_keys_from_misp_to_context_data({'Attribute': attributes_list})
    return formatted_response, score, found_tag, found_related_events


def prepare_attributes_array_to_context_data(attributes_list):
    attributes_tag_ids, event_tag_ids = set(), set()
    found_related_events = {}
    if not attributes_list:
        return None
    for attribute in attributes_list:
        attribute.pop("RelatedAttribute")  # get rid of this useless list
        event = attribute.get('Event')
        convert_timestamp_to_readable(attribute, event)
        found_related_events[event.get("id")] = {"Event Name": event.get("info"),
                                                 "Threat Level ID": event.get('threat_level_id'),
                                                 "Event ID": event.get("id")}
        if event.get('Tag'):
            limit_tag_output, tag_ids = limit_tag_output_to_id_and_name(event, True)
            event['Tag'] = limit_tag_output
            event_tag_ids.update(tag_ids)
        if attribute.get('Tag'):
            limit_tag_output, tag_ids = limit_tag_output_to_id_and_name(attribute, False)
            attribute['Tag'] = limit_tag_output
            attributes_tag_ids.update(tag_ids)
    return found_related_events, attributes_tag_ids, event_tag_ids


def convert_timestamp_to_readable(attribute, event):
    if attribute.get('timestamp'):
        attribute['timestamp'] = misp_convert_timestamp_to_date_string(attribute.get('timestamp'))
    if event:
        if event.get('timestamp'):
            attribute['Event']['timestamp'] = misp_convert_timestamp_to_date_string(event.get('timestamp'))
        if event.get('publish_timestamp'):
            attribute['Event']['publish_timestamp'] = misp_convert_timestamp_to_date_string(
                event.get('publish_timestamp'))


def found_event_with_bad_threat_level_id(found_related_events):
    bad_threat_level_ids = ["1", "2", "3"]
    return any(event["Threat Level ID"] in bad_threat_level_ids for event in found_related_events.values())


def get_score(attribute_tags_ids, event_tags_ids, malicious_tag_ids, suspicious_tag_ids, benign_tag_ids,
              is_attribute_in_event_with_bad_threat_level):
    """
    Calculates the indicator score by following logic. Indicators of attributes and Events that:
    * have tags which configured as malicious will be scored 3 (i.e malicious).
    * have tags which configured as suspicious will be scored 2 (i.e suspicious).
    * don't have any tags configured as suspicious nor malicious will be scored by their event's threat level id. In
    such case, the score will be BAD if the threat level id is in [1,2,3]. Otherwise, the threat level is 4 = Unknown.
    note:
    - In case the same tag appears in both Malicious tag ids and Suspicious tag ids lists the indicator will
      be scored as malicious.
    - Attributes tags (both malicious and suspicious) are stronger than events' tags.
    """
    found_tag = None
    is_attribute_tag_malicious = any((found_tag := tag) in attribute_tags_ids for tag in malicious_tag_ids)
    if is_attribute_tag_malicious:
        return Common.DBotScore.BAD, found_tag

    is_attribute_tag_suspicious = any((found_tag := tag) in attribute_tags_ids for tag in suspicious_tag_ids)
    if is_attribute_tag_suspicious:
        return Common.DBotScore.SUSPICIOUS, found_tag

    is_attribute_tag_benign = any((found_tag := tag) in attribute_tags_ids for tag in benign_tag_ids)
    if is_attribute_tag_benign:
        return Common.DBotScore.GOOD, found_tag

    is_event_tag_malicious = any((found_tag := tag) in event_tags_ids for tag in malicious_tag_ids)
    if is_event_tag_malicious:
        return Common.DBotScore.BAD, found_tag

    is_event_tag_suspicious = any((found_tag := tag) in event_tags_ids for tag in suspicious_tag_ids)
    if is_event_tag_suspicious:
        return Common.DBotScore.SUSPICIOUS, found_tag

    is_event_tag_benign = any((found_tag := tag) in event_tags_ids for tag in benign_tag_ids)
    if is_event_tag_benign:
        return Common.DBotScore.GOOD, found_tag

    # no tag was found
    if is_attribute_in_event_with_bad_threat_level:
        return Common.DBotScore.BAD, None

    return Common.DBotScore.NONE, None


def get_new_misp_event_object(args):
    """
    Create a new MISP event object and set the event's details.
    """
    event = MISPEvent()
    event.distribution = MISP_DISTRIBUTION_TO_IDS[args.get('distribution')]

    sharing_group_id = args.get('sharing_group_id')
    if event.distribution == 4 and not sharing_group_id:
        raise DemistoException("Error: When setting distribution to be 'Sharing_group', you have to specify the "
                               "'sharing_group_id' argument.")
    if sharing_group_id:
        event.sharing_group_id = arg_to_number(sharing_group_id)  # type: ignore[assignment]

    threat_level_id_arg = args.get('threat_level_id')
    if threat_level_id_arg:
        event.threat_level_id = THREAT_LEVELS_TO_ID[threat_level_id_arg]

    analysis_arg = args.get('analysis')
    event.analysis = MISP_ANALYSIS_TO_IDS.get(analysis_arg, analysis_arg)
    event.info = args.get('info') if args.get('info') else 'Event from XSOAR'
    event.date = datetime.strptime(args.get('creation_date'), "%Y-%m-%d") if args.get('creation_date') else datetime.today()
    event.published = argToBoolean(args.get('published', 'False'))
    return event


def create_event_command(demisto_args: dict):
    """Creating event in MISP with the given attribute args"""
    new_event = get_new_misp_event_object(demisto_args)
    new_event = PYMISP.add_event(new_event, True)

    if isinstance(new_event, dict):
        if new_event.get('errors'):
            raise DemistoException(f"Errors:{new_event.get('errors')}")
        raise DemistoException(f"Unknown event type:{type(new_event)}.")
    event_id = new_event.id
    add_attribute(event_id=event_id, internal=True, new_event=new_event, demisto_args=demisto_args)
    event = PYMISP.search(eventid=event_id)
    human_readable = f"## MISP create event\nNew event with ID: {event_id} has been successfully created.\n"

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='MISP.Event',
        outputs_key_field='ID',
        outputs=build_events_search_response(event),  # type: ignore[arg-type]
        raw_response=event
    )


def add_user_to_misp(demisto_args: dict = {}):
    """Adding a new user to MISP.

    Args:
        demisto_args (dict): Demisto args
    """
    new_user = MISPUser()
    new_user.email = demisto_args['email']
    new_user.org_id = demisto_args.get('org_id')
    new_user.role_id = demisto_args.get('role_id')
    new_user.password = demisto_args.get('password')
    response = PYMISP.add_user(new_user)
    if 'errors' in response:
        raise DemistoException(f'Failed to add user.\nError message: {response}')
    else:
        human_readable = f"## MISP add user\nNew user was added to MISP.\nEmail:{new_user.email}"
        response = response.get('User', {})
        return CommandResults(readable_output=human_readable,
                              raw_response=response,
                              outputs=response,
                              outputs_prefix='MISP.User')


def get_organizations_info():
    """
    Display organization ids and names.
    """
    organizations = PYMISP.organisations()
    org_info = []
    for organization in organizations:
        org_id = organization.get('Organisation', {}).get('id')  # type: ignore[union-attr]
        org_name = organization.get('Organisation', {}).get('name')  # type: ignore[union-attr]
        if org_id and org_name:
            org_info.append({'name': org_name, 'id': org_id})
    if org_info:
        human_readable = tableToMarkdown('MISP Organizations', org_info, headers=['id', 'name'], removeNull=True)
    else:
        human_readable = 'There are no organization ids and names'
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='MISP.Organization',
        outputs=org_info,
        raw_response=org_info
    )


def get_role_info():
    """
    Display role ids and names.
    """
    roles = PYMISP.roles()
    role_info = []
    for role in roles:
        role_name = role.get('Role', {}).get('name')  # type: ignore[union-attr]
        role_id = role.get('Role', {}).get('id')  # type: ignore[union-attr]
        if role_name and role_id:
            role_info.append({'name': role_name, 'id': role_id})
    if role_info:
        human_readable = tableToMarkdown('MISP Roles', role_info, headers=['id', 'name'], removeNull=True)
    else:
        human_readable = 'There are no role ids and names'
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='MISP.Role',
        outputs=role_info,
        raw_response=role_info
    )


def add_attribute(
    event_id: int | None = None, internal: bool = False, demisto_args: dict = {},
    new_event: MISPEvent | None = None
):
    """Adding attribute to a given MISP event object
    This function can be called as an independence command or as part of another command (create event for example)

    Args:
        event_id (int): Event ID to add attribute to
        internal (bool): if set to True, will not post results to Demisto
        demisto_args (dict): Demisto args
        new_event (MISPEvent): When this function was called from create event command, the attribute will be added to
        that existing event.
    """
    value = demisto_args.get('value')
    attributes_args = {
        'id': demisto_args.get('event_id'),  # misp event id
        'type': demisto_args.get('type', 'other'),
        'category': demisto_args.get('category', 'External analysis'),
        'to_ids': argToBoolean(demisto_args.get('to_ids', True)),
        'comment': demisto_args.get('comment'),
        'value': argToList(value)
    }
    event_id = event_id if event_id else arg_to_number(demisto_args.get('event_id'), "event_id")
    attributes_args.update({'id': event_id}) if event_id else None

    distribution = demisto_args.get('distribution')
    attributes_args.update({'distribution': MISP_DISTRIBUTION_TO_IDS[distribution]}) if distribution else None

    sharing_group_id = demisto_args.get('sharing_group_id')
    attributes_args.update({'sharing_group_id': sharing_group_id}) if sharing_group_id else None

    if not new_event:
        response = PYMISP.search(eventid=event_id, pythonify=True)
        if not response:
            raise DemistoException(
                f"Error: An event with the given id: {event_id} was not found in MISP. please check it once again")
        new_event = response[0]  # type: ignore[assignment,index]
        # response[0] is MISP event

    if not isinstance(new_event, MISPEvent):
        raise TypeError(f"Expected instance of MISPEvent, but got {type(new_event).__name__}: {new_event}")
    new_event.add_attribute(**attributes_args)
    PYMISP.update_event(event=new_event)
    if internal:
        return None

    value = attributes_args.get('value')
    updated_event = PYMISP.search(eventid=new_event.id, controller='attributes', value=value)
    human_readable = f"## MISP add attribute\nNew attribute: {value} was added to event id {new_event.id}.\n"
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='MISP.Attribute',
        outputs_key_field='ID',
        outputs=build_attributes_search_response(updated_event),  # type: ignore[arg-type]
        raw_response=updated_event
    )


def generic_reputation_command(demisto_args, reputation_type, dbot_type, malicious_tag_ids, suspicious_tag_ids, benign_tag_ids,
                               reliability, attributes_limit, search_warninglists: bool = False):
    reputation_value_list = argToList(demisto_args.get(reputation_type), ',')
    command_results = []
    for value in reputation_value_list:
        command_results.append(
            get_indicator_results(value, dbot_type, malicious_tag_ids, suspicious_tag_ids, benign_tag_ids, reliability,
                                  attributes_limit, search_warninglists))
    return command_results


def reputation_value_validation(value, dbot_type):
    if dbot_type == 'FILE':
        # hashFormat will be used only in output
        hash_format = get_hash_type(value)
        if hash_format == 'Unknown':
            raise DemistoException('Invalid hash length, enter file hash of format MD5, SHA-1 or SHA-256')
    if dbot_type == 'IP' and not is_ip_valid(value):
        raise DemistoException(f"Error: The given IP address: {value} is not valid")
    if dbot_type == 'DOMAIN' and not re.compile(DOMAIN_REGEX, regexFlags).match(value):
        raise DemistoException(f"Error: The given domain: {value} is not valid")
    if dbot_type == 'URL' and not re.compile(urlRegex, regexFlags).match(value):
        raise DemistoException(f"Error: The given url: {value} is not valid")
    if dbot_type == 'EMAIL' and not re.compile(emailRegex, regexFlags).match(value):
        raise DemistoException(f"Error: The given email address: {value} is not valid")


def get_indicator_results(
    value: str,
    dbot_type: str,
    malicious_tag_ids: set,
    suspicious_tag_ids: set,
    benign_tag_ids: set,
    reliability: DBotScoreReliability,
    attributes_limit: int,
    search_warninglists: bool = False
):
    """
    This function searches for the given attribute value in MISP and then calculates it's dbot score.
    The score is calculated by the tags ids (attribute tags and event tags).
    Args:
        value (str): The indicator value (an IP address, email address, domain, url or file hash).
        dbot_type (str): Indicator type (file, url, domain, email or ip).
        malicious_tag_ids (set): Tag ids should be recognised as malicious.
        suspicious_tag_ids (set): Tag ids should be recognised as suspicious
        benign_tag_ids (set): Tag ids should be recognised as benign
        reliability (DBotScoreReliability): integration reliability score.
        attributes_limit (int) : Limits the number of attributes that will be written to the context
        search_warninglists: (optional, bool): Should the warninglists be included?

    Returns:
        CommandResults includes all the indicator results.
    """
    reputation_value_validation(value, dbot_type)
    # if ALLOWED_ORGS is empty, then it equals to any. When specified, then it filters out all other orgs that are not requested
    if TO_IDS:
        # to_ids flag represents whether the attribute is meant to be actionable
        # Actionable defined attributes can be used in automated processes as a pattern for detection
        misp_response = PYMISP.search(
            value=value,
            controller='attributes',
            include_context=True,
            include_correlations=True,
            include_event_tags=True,
            enforce_warninglist=not search_warninglists,
            include_decay_score=True,
            includeSightings=True,
            to_ids=TO_IDS,
            org=ALLOWED_ORGS
        )
    else:
        misp_response = PYMISP.search(
            value=value,
            controller='attributes',
            include_context=True,
            include_correlations=True,
            include_event_tags=True,
            enforce_warninglist=not search_warninglists,
            include_decay_score=True,
            includeSightings=True,
            org=ALLOWED_ORGS
        )

    indicator_type = INDICATOR_TYPE_TO_DBOT_SCORE[dbot_type]
    is_indicator_found = misp_response and misp_response.get('Attribute')  # type: ignore[union-attr]
    if is_indicator_found:
        outputs, score, found_tag, found_related_events = parse_response_reputation_command(
            misp_response,  # type: ignore[arg-type]
            malicious_tag_ids,
            suspicious_tag_ids,
            benign_tag_ids,
            attributes_limit
        )
        dbot = Common.DBotScore(indicator=value, indicator_type=indicator_type,
                                score=score, reliability=reliability, malicious_description="Match found in MISP")
        indicator = get_dbot_indicator(dbot_type, dbot, value)
        all_attributes = outputs.get('Attribute')
        events_to_human_readable = get_events_related_to_scored_tag(all_attributes, found_tag)
        attribute_highlights = reputation_command_to_human_readable(all_attributes, score, events_to_human_readable)
        readable_output = tableToMarkdown(f'Results found in MISP for value: {value}', attribute_highlights,
                                          removeNull=True)
        readable_output += tableToMarkdown('Related events', list(found_related_events.values()))
        return CommandResults(indicator=indicator,
                              raw_response=misp_response,
                              outputs=all_attributes,
                              outputs_prefix='MISP.Attribute',
                              outputs_key_field='ID',
                              readable_output=readable_output)

    else:
        if search_warninglists:
            res: list = []
            human_readable: str = ""
            misp_warninglists_response = PYMISP.values_in_warninglist([value])
            if 'errors' in misp_warninglists_response:
                raise DemistoException(
                    f'Unable to validate against MISP warninglists!\nError message: {misp_warninglists_response}')
            if (misp_warninglists_response and isinstance(misp_warninglists_response, dict)
                    and len(misp_warninglists_response.items()) > 0):
                lists = list(misp_warninglists_response.values())[0]
                list_names: str = ",".join([x["name"] for x in lists])
                dbot = Common.DBotScore(
                    indicator=value,
                    indicator_type=indicator_type,
                    score=Common.DBotScore.GOOD, reliability=reliability,
                    malicious_description=f"Match found in MISP warninglist{list_names}"
                )
                res.append(
                    {
                        "Value": value,
                        "Count": len(lists),
                        "Lists": list_names,
                    }
                )
                human_readable = tableToMarkdown(
                    "MISP Warninglist matchings:",
                    res,
                    headers=["Value", "Lists", "Count"],
                )
                warninglist_indicator: Optional[Common.Indicator] = get_dbot_indicator(dbot_type, dbot, value)
                if not warninglist_indicator:
                    raise DemistoException(f'The indicator type {dbot_type} is unknown!')
                return CommandResults(
                    indicator=warninglist_indicator,
                    raw_response=misp_warninglists_response,
                    outputs="",
                    outputs_prefix='MISP.Attribute',
                    outputs_key_field='ID',
                    readable_output=human_readable
                )

        dbot = Common.DBotScore(indicator=value, indicator_type=indicator_type,
                                score=Common.DBotScore.NONE, reliability=reliability,
                                malicious_description="No results were found in MISP")
        indicator = get_dbot_indicator(dbot_type, dbot, value)
        return CommandResults(indicator=indicator,
                              readable_output=f"No attributes found in MISP for value: {value}")


def get_events_related_to_scored_tag(all_attributes, found_tag):
    """
    This function searches for all the events that have the tag (i.e found_tag) which caused the indicator to be scored
    as malicious or suspicious.
    Args:
        all_attributes (dict): The parsed response from the MISP search attribute request
        found_tag (str): The tag that was scored as malicious or suspicious. If no tag was found, then the score is
        Unknown so no events should be found.

    Returns:
        list includes all the events that were detected as related to the tag.
    """
    scored_events = []
    if found_tag:
        for attribute in all_attributes:
            event = attribute.get('Event', {})
            event_name = event.get('Info')
            scored_events.extend(search_events_with_scored_tag(event, found_tag, event_name))
            scored_events.extend(search_events_with_scored_tag(attribute, found_tag, event_name))
    return remove_duplicated_related_events(scored_events)


def remove_duplicated_related_events(related_events):
    related_events_no_duplicates = []
    for i in range(len(related_events)):
        if related_events[i] not in related_events[i + 1:]:
            related_events_no_duplicates.append(related_events[i])
    return related_events_no_duplicates


def search_events_with_scored_tag(object_data_dict, found_tag, event_name):
    """
    By the given object we go over all the tags and search if found_tag is one of it's tags. If so, the event will be
    added to related_events list
    Args:
        object_data_dict (dict): Event or attribute dict which includes tags list.
        found_tag (str): The tag that was scored as malicious or suspicious.
        event_name (str): Name of the event
    """
    related_events = []
    object_tags_list = object_data_dict.get('Tag', [])
    for tag in object_tags_list:
        if tag.get('ID') == found_tag:
            event_id = get_event_id(object_data_dict)
            tag_name = tag.get('Name')
            related_events.append({'Event_ID': event_id, 'Event_Name': event_name,
                                   'Tag_Name': tag_name, 'Tag_ID': tag.get('ID')})
    return related_events


def get_event_id(data_dict):
    if data_dict.get('EventID'):
        return data_dict.get('EventID')
    elif data_dict.get('ID'):
        return data_dict.get('ID')
    return data_dict.get('Event', {}).get('ID')


def get_dbot_indicator(
    dbot_type: str,
    dbot_score: Common.DBotScore,
    value: Any
) -> Optional[Common.Indicator]:
    """Converts dbot indicator information to an indicator object

    Args:
        dbot_type (str): The object type
        dbot_score (Common.DBotScore): The score of the indicator
        value (Any): The value of the indicator

    Returns:
        Optional[Common.Indicator]: The indicator object
    """

    if dbot_type == "FILE":
        hash_type = get_hash_type(value)
        if hash_type == 'md5':
            return Common.File(dbot_score=dbot_score, md5=value)
        if hash_type == 'sha1':
            return Common.File(dbot_score=dbot_score, sha1=value)
        if hash_type == 'sha256':
            return Common.File(dbot_score=dbot_score, sha256=value)
    if dbot_type == "IP":
        return Common.IP(ip=value, dbot_score=dbot_score)
    if dbot_type == "DOMAIN":
        return Common.Domain(domain=value, dbot_score=dbot_score)
    if dbot_type == "EMAIL":
        return Common.EMAIL(address=value, dbot_score=dbot_score)
    if dbot_type == "URL":
        return Common.URL(url=value, dbot_score=dbot_score)
    return None


def build_misp_complex_filter(demisto_query: str):
    """
    Examples are available in UT: test_build_misp_complex_filter.
    For more information please see build_complex_query in pymisp/api.py

    Args:
        demisto_query: complex query contains saved words: 'AND:', 'OR:' and 'NOT:'
            using ',' as delimiter for parameters and ';' as delimiter for operators.
            using the operators is optional.
            if 'demisto_query' does not contains any of the complex operators the original
            input will be returned

    Returns:
        str: dictionary created for misp to perform complex query
        or if no complex query found returns the original input
    """

    regex_and = r'(AND:)([^\;]+)(;)?'
    regex_or = r'(OR:)([^\;]+)(;)?'
    regex_not = r'(NOT:)([^\;]+)(;)?'
    misp_query_params: Dict[Any, Any] = {}

    match_and = re.search(regex_and, demisto_query, re.MULTILINE)
    match_or = re.search(regex_or, demisto_query, re.MULTILINE)
    match_not = re.search(regex_not, demisto_query, re.MULTILINE)

    is_complex_and_operator = is_misp_complex_search_helper(match_and, misp_query_params, 'and_parameters')
    is_complex_or_operator = is_misp_complex_search_helper(match_or, misp_query_params, 'or_parameters')
    is_complex_not_operator = is_misp_complex_search_helper(match_not, misp_query_params, 'not_parameters')
    is_complex_search = is_complex_and_operator or is_complex_or_operator or is_complex_not_operator
    if is_complex_search:
        return PYMISP.build_complex_query(**misp_query_params)
    return demisto_query


def is_misp_complex_search_helper(match_operator, misp_query_params, operator_key):
    is_complex_search = False
    if match_operator is not None:
        misp_query_params[operator_key] = match_operator.group(2).split(',')
        is_complex_search = True
    return is_complex_search


def prepare_args_to_search(controller):
    demisto_args = demisto.args()
    args_to_misp_format = {arg: demisto_args[arg] for arg in MISP_SEARCH_ARGUMENTS if arg in demisto_args}
    # Replacing keys and values from Demisto to Misp's keys
    if 'type' in args_to_misp_format:
        args_to_misp_format['type_attribute'] = args_to_misp_format.pop('type').split(",")
    if 'to_ids' in args_to_misp_format:
        args_to_misp_format['to_ids'] = 1 if demisto_args.get('to_ids') == 'true' else 0
    if 'from' in args_to_misp_format:
        args_to_misp_format['date_from'] = args_to_misp_format.pop('from')
    if 'to' in args_to_misp_format:
        args_to_misp_format['date_to'] = args_to_misp_format.pop('to')
    if 'event_id' in args_to_misp_format:
        args_to_misp_format['eventid'] = argToList(args_to_misp_format.pop('event_id'))
    if 'last' in args_to_misp_format:
        args_to_misp_format['publish_timestamp'] = args_to_misp_format.pop('last')
    if 'include_decay_score' in args_to_misp_format:
        args_to_misp_format['include_decay_score'] = 1 if demisto_args.get('include_decay_score') == 'true' else 0
    if 'include_sightings' in args_to_misp_format:
        args_to_misp_format['include_sightings'] = 1 if demisto_args.get('include_sightings') == 'true' else 0
    if 'include_correlations' in args_to_misp_format:
        args_to_misp_format['include_correlations'] = 1 if demisto_args.get('include_correlations') == 'true' else 0
    if 'enforceWarninglist' in args_to_misp_format:
        args_to_misp_format['enforceWarninglist'] = 1 if demisto_args.get('enforceWarninglist') == 'true' else 0
    if 'include_feed_correlations' in args_to_misp_format:
        args_to_misp_format['includeFeedCorrelations'] = 1 if demisto_args.get(
            'include_feed_correlations') == 'true' else 0
        args_to_misp_format.pop('include_feed_correlations')
    if 'limit' not in args_to_misp_format:
        args_to_misp_format['limit'] = '50'
    if 'tags' in args_to_misp_format:
        args_to_misp_format['tags'] = build_misp_complex_filter(args_to_misp_format['tags'])
    if args_to_misp_format.get('with_attachments') == 'true':
        args_to_misp_format['with_attachments'] = 1
    else:
        args_to_misp_format['with_attachments'] = 0
        args_to_misp_format['controller'] = controller
    demisto.debug(f"[MISP V3]: args for {demisto.command()} command are {args_to_misp_format}")
    return args_to_misp_format


def build_attributes_search_response(response: dict | requests.Response,
                                     include_correlations=False) -> dict:
    """
    Convert the response of attribute search returned from MISP to the context output format.
    """
    response_object = copy.deepcopy(response)
    if include_correlations:
        # return full related attributes only if the user wants to get them back
        ATTRIBUTE_FIELDS.append('RelatedAttribute')

    if isinstance(response_object, str):
        response_object = json.loads(json.dumps(response_object))
    if isinstance(response_object, dict):
        attributes = response_object.get('Attribute')
    else:  # Response
        attributes = response_object.json().get('Attribute')
    return get_limit_attribute_search_outputs(attributes)


def get_limit_attribute_search_outputs(attributes):
    for i in range(len(attributes)):
        attributes[i] = {key: attributes[i].get(key) for key in ATTRIBUTE_FIELDS if key in attributes[i]}
        build_galaxy_output(attributes[i])
        build_tag_output(attributes[i])
        build_sighting_output_from_attribute_search_response(attributes[i])
        convert_timestamp_to_readable(attributes[i], None)
    formatted_attributes = replace_keys_from_misp_to_context_data(attributes)
    return formatted_attributes


def build_galaxy_output(given_object):
    """given_object is attribute or event, depends on the called function"""
    if given_object.get('Galaxy'):
        given_object['Galaxy'] = [
            {
                'name': star.get('name'),
                'type': star.get('type'),
                'description': star.get('description')
            } for star in given_object['Galaxy']
        ]


def build_object_output(event):
    if event.get('Object'):
        event['Object'] = [
            {
                'name': event_object.get('name'),
                'uuid': event_object.get('uuid'),
                'description': event_object.get('description'),
                'id': event_object.get('id')
            } for event_object in event['Object']
        ]


def build_tag_output(given_object):
    """given_object is attribute or event, depends on the called function"""
    if given_object.get('Tag'):
        given_object['Tag'] = [
            {'Name': tag.get('name'),
             'is_galaxy': tag.get('is_galaxy')
             } for tag in given_object.get('Tag')
        ]


def build_sighting_output_from_attribute_search_response(attribute):
    if attribute.get('Sighting'):
        attribute['Sighting'] = [
            {'type': sighting.get('type')
             } for sighting in attribute.get('Sighting')
        ]


def build_attributes_search_response_return_only_values(response_object: dict | requests.Response) -> list:
    """returns list of attributes' values that match the search query when user set the arg 'compact' to True"""
    if isinstance(response_object, str):
        response_object = json.loads(json.dumps(response_object))
    if isinstance(response_object, dict):
        attributes = response_object.get('Attribute', [])
    else:  # Response
        attributes = response_object.json().get('Attribute', [])
    return [attribute.get('value') for attribute in attributes]


def pagination_args_validation(page, limit):
    if page and page < 0:
        raise DemistoException("page should be zero or a positive number")
    if limit and limit < 0:
        raise DemistoException("limit should be zero or a positive number")


def attribute_response_to_markdown_table(response: dict):
    attribute_highlights = []
    for attribute in response:
        event = attribute.get('Event', {})
        attribute_tags = [tag.get('Name') for tag in attribute.get('Tag')] if attribute.get(
            'Tag') else None
        attribute_sightings = [SIGHTING_TYPE_ID_TO_NAME[sighting.get('Type')] for sighting in
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
            'Timestamp': attribute.get('Timestamp'),
            'Event Info': event.get('Info'),
            'Event Organization ID': event.get('OrganizationID'),
            'Event Distribution': event.get('Distribution'),
            'Event UUID': event.get('UUID')
        })
    return attribute_highlights


def search_attributes(demisto_args: dict) -> CommandResults:
    """Execute a MISP search over 'attributes'"""
    args = prepare_args_to_search('attributes')
    outputs_should_include_only_values = argToBoolean(demisto_args.get('compact', False))
    include_correlations = argToBoolean(demisto_args.get('include_correlations', False))
    page = arg_to_number(demisto_args.get('page', 1), "page", required=True)
    limit = arg_to_number(demisto_args.get('limit', 50), "limit", required=True)
    pagination_args_validation(page, limit)

    response = PYMISP.search(**args)

    if response:
        response_for_context_list = []
        response_for_context_dict = {}

        if args.get('with_attachments', 0) == 1 and isinstance(response, list):
            for attachment in response:
                for objects in attachment.get('Event', {}).get('Object', []):
                    for object in objects.get('Attribute', []):
                        if args.get('value') == object.get('value'):
                            for object in objects.get('Attribute'):
                                if data := object.get('data'):
                                    res = fileResult('{}.zip'.format(args.get('value')), b64decode(data))
                                    demisto.results(res)

            demisto.args()['with_attachments'] = 'false'
            return search_attributes(demisto_args)

        if outputs_should_include_only_values:
            response_for_context_list = build_attributes_search_response_return_only_values(response)  # type: ignore[arg-type]
            number_of_results = len(response_for_context_list)
            md = tableToMarkdown(f"MISP search-attributes returned {number_of_results} attributes",
                                 response_for_context_list[:number_of_results], ["Value"])
        else:
            response_for_context_dict = build_attributes_search_response(response, include_correlations)  # type: ignore[arg-type]
            attribute_highlights = attribute_response_to_markdown_table(response_for_context_dict)

            pagination_message = f"Current page size: {limit}\n"
            if len(response_for_context_dict) == limit:
                pagination_message += f"Showing page {page} out others that may exist"
            else:
                pagination_message += f"Showing page {page}"
            md = tableToMarkdown(
                f"MISP search-attributes returned {len(response_for_context_dict)} attributes\n {pagination_message}",
                attribute_highlights, removeNull=True)

        response_for_context = response_for_context_list or response_for_context_dict

        return CommandResults(
            raw_response=response,
            readable_output=md,
            outputs=response_for_context,
            outputs_prefix="MISP.Attribute",
            outputs_key_field="ID"
        )

    else:
        return CommandResults(readable_output=f"No attributes found in MISP for the given filters: {args}")


def build_events_search_response(response: dict | requests.Response, demisto_args={}) -> dict:
    """
    Convert the response of event search returned from MISP to the context output format.
    please note: attributes are excluded from search-events output as the information is too big. User can use the
    command search-attributes in order to get the information about the attributes.
    Note: following the issue: 42650 we will return only attributes' feed hits on this command, for more info
    please read the issue.
    """
    response_object = copy.deepcopy(response)
    if isinstance(response_object, str):
        response_object = json.loads(json.dumps(response_object))
    if isinstance(response_object, requests.Response):
        events = [event.get('Event') for event in response_object.json()]
    else:  # dict
        events = [event.get('Event') for event in response_object]
    for i in range(0, len(events)):
        # Filter object from keys in event_args
        events[i] = {key: events[i].get(key) for key in EVENT_FIELDS if key in events[i]}
        events[i]['RelatedEvent'] = []  # there is no need in returning related event when searching for an event
        build_galaxy_output(events[i])
        build_tag_output(events[i])
        build_object_output(events[i])
        build_attribute_feed_hit(events[i], demisto_args)
        events[i]['timestamp'] = misp_convert_timestamp_to_date_string(events[i].get('timestamp'))
        events[i]['publish_timestamp'] = misp_convert_timestamp_to_date_string(events[i].get('publish_timestamp'))

    formatted_events = replace_keys_from_misp_to_context_data(events)  # type: ignore
    return formatted_events  # type: ignore


def build_attribute_feed_hit(event: dict, demisto_args):
    """
    We want to have the attributes data as part of the search-events context results only if the user asked for
    include_feed_correlations. The data we return includes some finite fields:
    * A list of event_uuids, feed ID, name, provider, source format and a url. None of these fields doesn't include
    some heavy data which can cause performance issues.
    Otherwise, we don't want to return attributes data at all.
    """
    if argToBoolean(demisto_args.get('include_feed_correlations', False)):
        if event.get('Attribute'):
            event['Attribute'] = [
                {
                    'id': attribute.get('id'),
                    'value': attribute.get('value'),
                    'Feed': attribute.get('Feed')
                } for attribute in event['Attribute']
            ]
    else:
        event.pop('Attribute')


def event_to_human_readable_tag_list(event):
    event_tags = event.get('Tag', [])
    if event_tags:
        return [tag.get('Name') for tag in event_tags]
    return None


def event_to_human_readable_galaxy_list(event):
    event_galaxies = event.get('Galaxy', [])
    if event_galaxies:
        return [galaxy.get('Name') for galaxy in event.get('Galaxy')]
    return None


def event_to_human_readable_object_list(event):
    event_objects = event.get('Object', [])
    if event_objects:
        return [event_object.get('ID') for event_object in event.get('Object')]
    return None


def event_to_human_readable(response: dict):
    event_highlights = []
    for event in response:
        event_tags = event_to_human_readable_tag_list(event)
        event_galaxies = event_to_human_readable_galaxy_list(event)
        event_objects = event_to_human_readable_object_list(event)
        event_highlights.append({
            'Event ID': event.get('ID'),
            'Event Tags': event_tags,
            'Event Galaxies': event_galaxies,
            'Event Objects': event_objects,
            'Publish Timestamp': event.get('PublishTimestamp'),
            'Event Info': event.get('Info'),
            'Event Org ID': event.get('OrganizationID'),
            'Event Orgc ID': event.get('OwnerOrganization.ID'),
            'Event Distribution': event.get('Distribution'),
            'Event UUID': event.get('UUID'),
        })
    return event_highlights


def search_events(demisto_args: dict) -> CommandResults:
    """
    Execute a MISP search using the 'event' controller.
    """
    args = prepare_args_to_search('events')
    page = arg_to_number(demisto_args.get('page', 1), "page", required=True)
    limit = arg_to_number(demisto_args.get('limit', 50), "limit", required=True)
    pagination_args_validation(page, limit)

    response = PYMISP.search(**args)
    if response:
        response_for_context = build_events_search_response(response, demisto_args)  # type: ignore[arg-type]
        event_outputs_to_human_readable = event_to_human_readable(response_for_context)

        pagination_message = f"Current page size: {limit}\n"
        if len(response_for_context) == limit:
            pagination_message += f"Showing page {page} out others that may exist"
        else:
            pagination_message += f"Showing page {page}"
        md = tableToMarkdown(
            f"MISP search-events returned {len(response_for_context)} events.\n {pagination_message}",
            event_outputs_to_human_readable, removeNull=True)

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
    event_id = demisto_args['event_id']
    response = PYMISP.delete_event(event_id)
    if 'errors' in response:
        raise DemistoException(f'Event ID: {event_id} has not found in MISP: \nError message: {response}')
    else:
        human_readable = f'Event {event_id} has been deleted'
        return CommandResults(readable_output=human_readable, raw_response=response)


def add_tag(demisto_args: dict, is_attribute=False):
    """
    Function will add tag to given UUID of event or attribute.
    is_attribute (bool): if the given UUID belongs to an attribute (True) or event (False).
    """
    uuid = demisto_args['uuid']
    tag = demisto_args['tag']
    is_local_tag = argToBoolean(demisto_args.get('is_local', False))
    disable_output = argToBoolean(demisto_args.get('disable_output', False))
    try:
        PYMISP.tag(uuid, tag, local=is_local_tag)  # add the tag
    except PyMISPError:
        raise DemistoException("Adding the required tag was failed. Please make sure the UUID exists.")
    if is_attribute:
        response = None
        success_msg = f'Tag {tag} has been successfully added to attribute {uuid}'
        if not disable_output:
            response = PYMISP.search(uuid=uuid, controller='attributes')
            return CommandResults(
                readable_output=success_msg,
                outputs_prefix='MISP.Attribute',
                outputs_key_field='ID',
                outputs=build_attributes_search_response(response),  # type: ignore[arg-type]
                raw_response=response
            )
        else:
            return CommandResults(
                readable_output=success_msg,
                raw_response=success_msg
            )

    # event's uuid
    response = PYMISP.search(uuid=uuid)
    human_readable = f'Tag {tag} has been successfully added to event {uuid}'
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='MISP.Event',
        outputs_key_field='ID',
        outputs=build_events_search_response(response),  # type: ignore[arg-type]
        raw_response=response
    )


def remove_tag(demisto_args: dict, is_attribute=False):
    """
    Function will remove tag to given UUID of event or attribute.
    is_attribute (bool): if the given UUID is an attribute's one. Otherwise it's event's.
    """
    uuid = demisto_args['uuid']
    tag = demisto_args['tag']
    try:
        response = PYMISP.untag(uuid, tag)
        if response and response.get('errors'):  # type: ignore[union-attr]
            raise DemistoException(f'Error in `{demisto.command()}` command: {response}')
    except PyMISPError:
        raise DemistoException("Removing the required tag was failed. Please make sure the UUID and tag exist.")

    if is_attribute:
        response = PYMISP.search(uuid=uuid, controller='attributes')  # type: ignore[assignment]
        human_readable = f'Tag {tag} has been successfully removed from the attribute {uuid}'
        return CommandResults(
            readable_output=human_readable,
            outputs_prefix='MISP.Attribute',
            outputs_key_field='ID',
            outputs=build_attributes_search_response(response),  # type: ignore[arg-type]
            raw_response=response
        )
    # event's uuid
    response = PYMISP.search(uuid=uuid)  # type: ignore[assignment]
    human_readable = f'Tag {tag} has been successfully removed from the event {uuid}'
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='MISP.Event',
        outputs_key_field='ID',
        outputs=build_events_search_response(response),  # type: ignore[arg-type]
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
        raise DemistoException('ID or UUID not specified')
    sighting_args = {
        'id': attribute_id,
        'uuid': attribute_uuid,
        'type': SIGHTING_TYPE_NAME_TO_ID[sighting_type]
    }
    sigh_obj = MISPSighting()
    sigh_obj.from_dict(**sighting_args)
    response = PYMISP.add_sighting(sigh_obj, att_id)
    if response.get('message'):
        raise DemistoException(f"An error was occurred: {response.get('message')}")
    elif response.get('Sighting'):
        human_readable = f'Sighting \'{sighting_type}\' has been successfully added to attribute {att_id}'
        return CommandResults(readable_output=human_readable)
    raise DemistoException(f"An error was occurred: {json.dumps(response)}")


def test(malicious_tag_ids, suspicious_tag_ids, attributes_limit):
    """
    Test module.
    """
    is_tag_list_valid(malicious_tag_ids)
    is_tag_list_valid(suspicious_tag_ids)
    if attributes_limit < 0:
        raise DemistoException('Attribute limit has to be a positive number.')
    response = PYMISP._prepare_request('GET', 'servers/getPyMISPVersion.json')
    if PYMISP._check_json_response(response):
        return 'ok'
    else:
        raise DemistoException('MISP has not connected.')


def build_feed_url(demisto_args):
    url = demisto_args.get('feed')
    url = url[:-1] if url.endswith('/') else url
    if PREDEFINED_FEEDS.get(url):
        url = PREDEFINED_FEEDS[url].get('url')  # type: ignore
    return url


def add_events_from_feed(demisto_args: dict, use_ssl: bool, proxies: dict):
    """Gets an OSINT feed from url and publishing them to MISP
    urls with feeds for example: https://www.misp-project.org/feeds/
    feed format must be MISP.
    """
    headers = {'Accept': 'application/json'}
    url = build_feed_url(demisto_args)
    osint_url = f'{url}/manifest.json'
    limit = arg_to_number(demisto_args.get('limit', 2), "limit", required=True)
    try:
        uri_list = requests.get(osint_url, verify=use_ssl, headers=headers, proxies=proxies).json()
        events_ids = []  # type: List[Dict[str, int]]
        for _index, uri in enumerate(uri_list, 1):
            response = requests.get(f'{url}/{uri}.json', verify=use_ssl, headers=headers, proxies=proxies).json()
            misp_new_event = MISPEvent()
            misp_new_event.load(response)
            add_event_response = PYMISP.add_event(misp_new_event)
            event_object = add_event_response.get('Event')
            if event_object and 'id' in event_object:
                events_ids.append({'ID': event_object['id']})
            if limit == len(events_ids):
                break
        human_readable = tableToMarkdown(f'Total of {len(events_ids)} events was added to MISP.', events_ids)
        return CommandResults(
            readable_output=human_readable,
            outputs_prefix='MISP.Event',
            outputs_key_field='ID',
            outputs=events_ids,
        )
    except ValueError as e:
        raise DemistoException(f'URL [{url}] is not a valid MISP feed. error: {e}')


def add_object(event_id: str, obj: MISPObject):
    """Sending object to MISP and returning outputs

    Args:
        obj: object to add to MISP
        event_id: ID of event
    """
    try:
        response = PYMISP.add_object(event_id, misp_object=obj)
    except MISPServerError as error:
        raise DemistoException(f'Error in `{demisto.command()}` error: {error}')
    if 'errors' in response:
        raise DemistoException(f'Error in `{demisto.command()}` command: {response}')
    for ref in obj.ObjectReference:
        response = PYMISP.add_object_reference(ref)  # type: ignore[assignment]
    for attribute in response.get('Object', {}).get('Attribute', []):
        convert_timestamp_to_readable(attribute, None)
    response['Object']['timestamp'] = misp_convert_timestamp_to_date_string(response.get('Object', {}).get('timestamp'))
    formatted_response = replace_keys_from_misp_to_context_data(response)  # type: ignore[assignment, arg-type]
    if isinstance(formatted_response, str):
        formatted_response = f'{formatted_response} ID:{event_id}'
    elif isinstance(formatted_response, dict):
        formatted_response.update({"ID": event_id})
    else:
        formatted_response.append({"ID": event_id})

    human_readable = f'Object has been added to MISP event ID {event_id}'
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='MISP.Event',
        outputs_key_field='ID',
        outputs=formatted_response,
    )


def add_file_object(demisto_args: dict):
    entry_id = demisto_args.get('entry_id')
    event_id = demisto_args.get('event_id', '')
    file_path = demisto.getFilePath(entry_id).get('path')
    obj = FileObject(file_path)
    return add_object(event_id, obj)


def add_email_object(demisto_args: dict):
    entry_id = demisto_args.get('entry_id')
    event_id = demisto_args.get('event_id', '')
    email_path = demisto.getFilePath(entry_id).get('path')
    name = demisto.getFilePath(entry_id).get('name', '')
    if name.endswith(".msg"):
        raise DemistoException(
            'misp-add-email-object command does not support *.msg files, please use an *.eml file type instead.')
    obj = EMailObject(email_path)
    return add_object(event_id, obj)


def add_domain_object(demisto_args: dict):
    """Adds a domain object to MISP
    domain-ip description: https://www.misp-project.org/objects.html#_domain_ip
    """
    text = demisto_args.get('text')
    event_id = demisto_args.get('event_id', '')
    domain = demisto_args.get('name')
    obj = MISPObject('domain-ip')
    ips = argToList(demisto_args.get('ip'))
    for ip in ips:
        obj.add_attribute('ip', value=ip)
    obj.add_attribute('domain', value=domain)
    if text:
        obj.add_attribute('text', value=text)
    return add_object(event_id, obj)


def add_url_object(demisto_args: dict):
    """Building url object in MISP scheme
    Scheme described https://www.misp-project.org/objects.html#_url
    """
    url_args = [
        'text',
        'last_seen',
        'first_seen'
    ]
    event_id = demisto_args.get('event_id', '')
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
    return add_object(event_id, g_object)


def add_generic_object_command(demisto_args: dict):
    event_id = demisto_args.get('event_id', '')
    template = demisto_args.get('template', '')
    attributes = demisto_args.get('attributes', '').replace("'", '"')
    try:
        args = json.loads(attributes)
        if not isinstance(args, list):
            args = dict_to_generic_object_format(args)
        obj = build_generic_object(template, args)
        return add_object(event_id, obj)
    except ValueError as e:
        raise DemistoException(
            f'`attribute` parameter could not be decoded, may not a valid JSON\nattribute: {attributes}', str(e))


def add_custom_object_command(demisto_args: dict):
    event_id = demisto_args.get('event_id', '')
    template = demisto_args.get('template', '')
    attributes = demisto_args.get('attributes', '').replace("'", '"')

    try:
        args = json.loads(attributes)
        if not isinstance(args, list):
            args = dict_to_generic_object_format(args)

        obj = build_custom_object(template, args)
        if obj is not False:
            return add_object(event_id, obj)
        else:
            raise DemistoException(f'Unable to find custom template {template}')

    except ValueError as e:
        raise DemistoException(
            f'`attribute` parameter could not be decoded, may not a valid JSON\nattribute: {attributes}', str(e))


def convert_arg_to_misp_args(demisto_args, args_names):
    return [{arg.replace('_', '-'): demisto_args.get(arg)} for arg in args_names if demisto_args.get(arg)]


def add_ip_object(demisto_args: dict):
    event_id = demisto_args.get('event_id', '')
    ip_object_args = [
        'dst_port',
        'src_port',
        'domain',
        'hostname',
        'ip_src',
        'ip_dst'
    ]
    # converting args to MISP's arguments types
    misp_attributes_args = convert_arg_to_misp_args(demisto_args, ip_object_args)
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
        raise DemistoException(
            f'None of required arguments presents. command {demisto.command()} requires one of {ip_object_args}')


def handle_tag_duplication_ids(malicious_tag_ids: list, suspicious_tag_ids: list, benign_tag_ids: list):
    """
    Gets 2 sets which include tag ids. If there is an id that exists in both sets, it will be removed from the
    suspicious tag ids set and will be stayed only in the malicious one (as a tag that was configured to be malicious is
    stronger than recognised as suspicious).
    """
    common_ids = set(malicious_tag_ids) & set(suspicious_tag_ids)
    common_ids_sus = set(suspicious_tag_ids) & set(benign_tag_ids)
    common_ids_mal = set(malicious_tag_ids) & set(benign_tag_ids)
    suspicious_tag_ids = list({tag_id for tag_id in suspicious_tag_ids if tag_id not in common_ids})
    benign_tag_ids = list({tag_id for tag_id in benign_tag_ids if tag_id not in common_ids_sus and tag_id not in common_ids_mal})
    return malicious_tag_ids, suspicious_tag_ids, benign_tag_ids


def is_tag_list_valid(tag_ids):
    """Gets a list ot tag ids (each one is str), and verify all the tags are valid positive integers."""
    for tag in tag_ids:
        try:
            tag = int(tag)
            if tag <= 0:
                raise DemistoException(f"Tag id has to be a positive integer, please change the given: '{tag}' id.")
        except ValueError:
            raise DemistoException(f"Tag id has to be a positive integer, please change the given: '{tag}' id.")


def create_updated_attribute_instance(demisto_args: dict, attribute_uuid: str) -> MISPAttribute:
    attribute_type = demisto_args.get('type')
    distribution = demisto_args.get('distribution')
    category = demisto_args.get('category')
    comment = demisto_args.get('comment')
    value = demisto_args.get('value')
    first_seen = demisto_args.get('first_seen')
    last_seen = demisto_args.get('last_seen')

    attribute_instance = MISPAttribute()
    attribute_instance.uuid = attribute_uuid
    if attribute_type:
        attribute_instance.type = attribute_type
    if distribution:
        attribute_instance.distribution = MISP_DISTRIBUTION_TO_IDS[distribution]
    if category:
        attribute_instance.category = category
    if value:
        attribute_instance.value = value
    if comment:
        attribute_instance.comment = comment
    if first_seen:
        attribute_instance.first_seen = first_seen
    if last_seen:
        attribute_instance.last_seen = last_seen
    return attribute_instance


def update_attribute_command(demisto_args: dict) -> CommandResults:
    attribute_uuid = demisto_args.get('attribute_uuid', '')
    attribute_instance = create_updated_attribute_instance(demisto_args, attribute_uuid)
    attribute_instance_response = PYMISP.update_attribute(attribute=attribute_instance, attribute_id=attribute_uuid)
    if isinstance(attribute_instance_response, dict) and attribute_instance_response.get('errors'):
        raise DemistoException(attribute_instance_response.get('errors'))

    human_readable = f"## MISP update attribute\nAttribute: {attribute_uuid} was updated.\n"
    attribute = attribute_instance_response.get('Attribute')
    convert_timestamp_to_readable(attribute, None)
    parsed_attribute_data = replace_keys_from_misp_to_context_data(attribute)  # type: ignore[arg-type]

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='MISP.Attribute',
        outputs_key_field='ID',
        outputs=parsed_attribute_data,
    )


def delete_attribute_command(demisto_args: dict) -> CommandResults:
    """
    Gets an attribute id and deletes it.
    """
    attribute_id = demisto_args['attribute_id']
    response = PYMISP.delete_attribute(attribute_id)
    if 'errors' in response:
        raise DemistoException(f'Attribute ID: {attribute_id} has not found in MISP: \nError message: {response}')
    else:
        human_readable = f'Attribute {attribute_id} has been deleted'
        return CommandResults(readable_output=human_readable, raw_response=response)


def publish_event_command(demisto_args: dict) -> CommandResults:
    """
    Gets an event id and publishes it.
    """
    event_id = demisto_args['event_id']
    alert = argToBoolean(demisto_args.get('alert', False))
    response = PYMISP.publish(event_id, alert=alert)
    if 'errors' in response:
        raise DemistoException(f'Event ID: {event_id} has not found in MISP: \nError message: {response}')
    else:
        human_readable = f'Event {event_id} has been published'
        return CommandResults(readable_output=human_readable, raw_response=response)


def set_event_attributes_command(demisto_args: dict) -> CommandResults:
    """
    Set the attributes of an event according to given alert_data.
    """
    changed = False
    event_id = demisto_args['event_id']
    event = PYMISP.get_event(event_id, pythonify=True)
    if 'errors' in event:
        raise DemistoException(f'Event ID: {event_id} has not found in MISP: \nError message: {event}')
    try:
        attribute_data = json.loads(demisto_args.get("attribute_data", ''))
    except Exception as e:
        raise DemistoException(f'Invalid attribute_data: \nError message: {str(e)}')

    if not isinstance(event, MISPEvent):
        raise TypeError(f"Expected instance of MISPEvent, but got {type(event).__name__}: {event}")
    for event_attribute in event.attributes:
        if event_attribute["value"] not in [x["value"] for x in attribute_data]:
            event_attribute.delete()
            changed = True
    for attribute in attribute_data:
        if attribute["value"] not in [x["value"] for x in event.attributes]:
            event.add_attribute(attribute["type"], attribute["value"])
            changed = True
    if changed:
        event_update = PYMISP.update_event(event=event)
        if 'errors' in event_update:
            raise DemistoException(f'Event ID: {event_id} could not be updated: \nError message: {event_update}')
        else:
            human_readable = f'Attributes of Event {event_id} were set to match attribute data.'
            return CommandResults(readable_output=human_readable, raw_response=event_update)
    else:
        return CommandResults(readable_output="No changes to event.")


def warninglist_command(demisto_args: dict) -> CommandResults:
    """
    Check values against MISP warninglists.
    """
    res = []
    values = argToList(demisto_args["value"])
    response = PYMISP.values_in_warninglist(values)
    if 'errors' in response:
        raise DemistoException(f'Unable to validate against MISPwarninglist!\nError message: {response}')
    if not response:
        return CommandResults(
            readable_output="No value is on a MISP warning list!",
            raw_response=response,
        )
    for value, lists in response.items():  # type: ignore[union-attr]
        if len(lists) > 0:
            res.append(
                {
                    "Value": value,
                    "Count": len(lists),
                    "Lists": ",".join([x["name"] for x in lists]),
                }
            )
    human_readable = tableToMarkdown(
        "MISP Warninglist matchings:",
        sorted(res, key=lambda x: x["Count"], reverse=True),
        headers=["Value", "Lists", "Count"],
    )
    return CommandResults(
        outputs=res,
        outputs_prefix="MISP.Warninglist",
        outputs_key_field=["Value"],
        readable_output=human_readable,
        raw_response=response,
    )


def main():
    params = demisto.params()
    malicious_tag_ids = argToList(params.get('malicious_tag_ids'))
    suspicious_tag_ids = argToList(params.get('suspicious_tag_ids'))
    benign_tag_ids = argToList(params.get('benign_tag_ids'))
    search_warninglists: bool = argToBoolean(params.get('search_warninglists', False))
    reliability = params.get('integrationReliability', 'B - Usually reliable')
    if DBotScoreReliability.is_valid_type(reliability):
        reliability = DBotScoreReliability.get_dbot_score_reliability_from_str(reliability)
    else:
        Exception("MISP V3 error: Please provide a valid value for the Source Reliability parameter")
    attributes_limit = arg_to_number(params.get('attributes_limit', 20), "attributes_limit", required=True)
    command = demisto.command()
    demisto.debug(f'[MISP V3]: command is {command}')
    args = demisto.args()

    try:

        malicious_tag_ids, suspicious_tag_ids, benign_tag_ids = handle_tag_duplication_ids(
            malicious_tag_ids, suspicious_tag_ids, benign_tag_ids)
        if command == 'test-module':
            return_results(test(malicious_tag_ids=malicious_tag_ids, suspicious_tag_ids=suspicious_tag_ids,
                                attributes_limit=attributes_limit))
        elif command == 'misp-create-event':
            return_results(create_event_command(args))
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
            return_results(add_events_from_feed(demisto_args=args, use_ssl=VERIFY, proxies=PROXIES))
        elif command == 'file':
            return_results(
                generic_reputation_command(args, 'file', 'FILE', malicious_tag_ids, suspicious_tag_ids, benign_tag_ids,
                                           reliability, attributes_limit, search_warninglists))
        elif command == 'url':
            return_results(
                generic_reputation_command(args, 'url', 'URL', malicious_tag_ids, suspicious_tag_ids, benign_tag_ids, reliability,
                                           attributes_limit, search_warninglists))
        elif command == 'ip':
            return_results(
                generic_reputation_command(args, 'ip', 'IP', malicious_tag_ids, suspicious_tag_ids, benign_tag_ids,
                                           reliability, attributes_limit, search_warninglists))
        elif command == 'domain':
            return_results(
                generic_reputation_command(args, 'domain', 'DOMAIN', malicious_tag_ids, suspicious_tag_ids,
                                           benign_tag_ids, reliability, attributes_limit, search_warninglists))
        elif command == 'email':
            return_results(generic_reputation_command(args, 'email', 'EMAIL', malicious_tag_ids, suspicious_tag_ids,
                                                      benign_tag_ids, reliability, attributes_limit, search_warninglists))
        elif command == 'misp-add-file-object':
            return_results(add_file_object(args))
        elif command == 'misp-add-email-object':
            return_results(add_email_object(args))
        elif command == 'misp-add-domain-object':
            return_results(add_domain_object(args))
        elif command == 'misp-add-url-object':
            return_results(add_url_object(args))
        elif command == 'misp-add-ip-object':
            return_results(add_ip_object(args))
        elif command == 'misp-add-object':
            return_results(add_generic_object_command(args))
        elif command == 'misp-add-custom-object':
            return_results(add_custom_object_command(args))
        elif command == 'misp-update-attribute':
            return_results(update_attribute_command(args))
        elif command == 'misp-delete-attribute':
            return_results(delete_attribute_command(args))
        elif command == 'misp-publish-event':
            return_results(publish_event_command(args))
        elif command == "misp-set-event-attributes":
            return_results(set_event_attributes_command(args))
        elif command == "misp-check-warninglist":
            return_results(warninglist_command(args))
        elif command == "misp-add-user":
            return_results(add_user_to_misp(args))
        elif command == "misp-get-organization-info":
            return_results(get_organizations_info())
        elif command == "misp-get-role-info":
            return_results(get_role_info())
    except PyMISPError as e:
        return_error(e.message)
    except Exception as e:
        return_error(str(e))


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
