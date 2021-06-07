# type: ignore
import base64
import logging
import warnings
import zipfile
from io import BytesIO
from typing import Union, List, Any, Tuple, Dict
from urllib.parse import urlparse, urljoin

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
MAX_ATTRIBUTES = 1000
MISP_PATH = 'MISP.Event(obj.ID === val.ID)'
MISP_ATTRIBUTE_PATH = 'MISP.Attribute(obj.ID === val.ID)'

"""
dict format :
    MISP key:DEMISTO key
"""
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
    'decay_score': 'DecayScore'
}

THREAT_LEVELS_WORDS = {
    '1': 'HIGH',
    '2': 'MEDIUM',
    '3': 'LOW',
    '4': 'UNDEFINED'
}

THREAT_LEVELS_NUMBERS = {
    'high': 1,
    'medium': 2,
    'low': 3,
    'undefined': 4
}

ANALYSIS_WORDS = {
    '0': 'Initial',
    '1': 'Ongoing',
    '2': 'Completed'
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
    'All_communities': 3
}

SIGHTING_MAP = {
    'sighting': 0,
    'false_positive': 1,
    'expiration': 2
}

''' HELPER FUNCTIONS '''


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
        template_name: template name as described in
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
    return datetime.utcfromtimestamp(int(timestamp)).strftime('%Y-%m-%d %H:%M:%S')


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


def remove_unselected_context_keys(context_data, data_keys_to_save=[]):
    for attribute in context_data['Attribute']:
        for key in list(attribute.keys()):
            if key not in data_keys_to_save:
                del attribute[key]


def limit_attributes_count(event: dict) -> dict:
    """
    Gets a MISP's event and limiting the amount of attributes to MAX_ATTRIBUTES

    Args:
       event (dict): MISP's event
    Returns:
        dict: context output
    """
    if event and 'Attribute' in event and len(event['Attribute']) > MAX_ATTRIBUTES:
        attributes = event['Attribute']
        attributes_num = len(attributes)
        event_id = event.get('id', '')
        event_uuid = event.get('uuid')
        demisto.info(f'Limiting amount of attributes in event to {MAX_ATTRIBUTES} '
                     f'to keep context from being overwhelmed. '
                     f'This limit can be changed in the integration configuration. '
                     f'Event ID: {event_id}, Event UUID: {event_uuid}, Attributes in event: {attributes_num}')
        sorted_attributes = sorted(attributes, key=lambda at: int(at.get('timestamp', 0)))
        event['Attribute'] = sorted_attributes[attributes_num - MAX_ATTRIBUTES:]
        return event
    return event


def arrange_context_according_to_user_selection(context_data, data_keys_to_save=[]):
    if not data_keys_to_save:
        return

    # each related event has it's own attributes
    for event in context_data:
        # Remove filtered fields in event
        remove_unselected_context_keys(event, data_keys_to_save)
        # Remove filtered fields in object
        for obj in event['Object']:
            remove_unselected_context_keys(obj, data_keys_to_save)


def build_context(response: Union[dict, requests.Response], data_keys_to_save=[]) -> dict:  # type: ignore
    """
    Gets a MISP's response and building it to be in context. If missing key, will return the one written.

    Args:
       response (requests.Response or dict):
       data_keys_to_save (list):
    Returns:
        dict: context output
    """
    event_args = [
        'id',
        'date',
        'threat_level_id',
        'info',
        'published',
        'uuid',
        'analysis',
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
        'Attribute',
        'ShadowAttribute',
        'RelatedEvent',
        'Galaxy',
        'Tag',
        'Object'
    ]
    # Sometimes, PyMISP will return str instead of a dict. json.loads() wouldn't work unless we'll dumps it first
    if isinstance(response, str):
        response = json.loads(json.dumps(response))
    # Remove 'Event' keyword
    events = [event.get('Event') for event in response]  # type: ignore
    for i in range(0, len(events)):
        events[i] = limit_attributes_count(events[i])

        # Filter object from keys in event_args
        events[i] = {
            key: events[i].get(key)
            for key in event_args if key in events[i]
        }

        # Remove 'Event' keyword from 'RelatedEvent'
        if events[i].get('RelatedEvent'):
            events[i]['RelatedEvent'] = [
                r_event.get('Event') for r_event in events[i].get('RelatedEvent')
            ]

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
                {'Name': tag.get('name')} for tag in events[i].get('Tag')
            ]
    events = replace_keys(events)  # type: ignore
    arrange_context_according_to_user_selection(events, data_keys_to_save)  # type: ignore
    return events  # type: ignore


def build_attribute_context(response: Union[dict, requests.Response]) -> dict:
    """
    Convert the response of attribute search returned from MIPS to the context output format.
    """
    attribute_fields = [
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
        'value',
        'Event',
        'Object',
        'Galaxy',  # field wasn't tested as we don't see it in our responses. Was added by customer's request.
        'Tag',
        'decay_score'
    ]
    if isinstance(response, str):
        response = json.loads(json.dumps(response))
    attributes = response.get('Attribute')
    for i in range(len(attributes)):
        attributes[i] = {key: attributes[i].get(key) for key in attribute_fields if key in attributes[i]}

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
                {'Name': tag.get('name')} for tag in attributes[i].get('Tag')
            ]

    attributes = replace_keys(attributes)
    return attributes


def get_misp_threat_level(threat_level_id: str) -> str:  # type: ignore
    """Gets MISP's thread level and returning it in Demisto's format

    Args:
        threat_level_id: str of thread level in MISP

    Returns:
        str: Threat-level in Demisto
    """
    if threat_level_id == '1':
        return 'HIGH'
    if threat_level_id == '2':
        return 'MEDIUM'
    if threat_level_id == '3':
        return 'LOW'
    if threat_level_id == '4':
        return 'UNDEFINED'
    return_error('Invalid MISP Threat Level with threat_level_id: ' + threat_level_id)


def get_dbot_level(threat_level_id: str) -> int:
    """
    MISP to DBOT:
    4 = 0 (UNDEFINED to UNKNOWN)
    3 = 2 (LOW to SUSPICIOUS)
    1 | 2 = 3 (MED/HIGH to MALICIOUS)
    Args:
        threat_level_id (str):
    Returns:
        int: DBOT score
    """
    if threat_level_id in ('1', '2'):
        return 3
    if threat_level_id == '3':
        return 2
    if threat_level_id == '4':
        return 0
    return 0


def get_files_events():
    files = argToList(demisto.args().get('file'), ',')
    for file_hash in files:
        check_file(file_hash)


def check_file(file_hash):
    """
    gets a file_hash and entities dict, returns MISP events

    file_hash (str): File's hash from demisto

    Returns:
        dict: MISP's output formatted to demisto:
    """
    # hashFormat will be used only in output
    hash_format = get_hash_type(file_hash).upper()
    if hash_format == 'Unknown':
        return_error('Invalid hash length, enter file hash of format MD5, SHA-1 or SHA-256')

    # misp_response will remain the raw output of misp
    misp_response = MISP.search(value=file_hash)
    if misp_response:
        dbot_list = list()
        file_list = list()
        md_list = list()
        for i_event in misp_response:
            event = i_event['Event']
            i_event['Event']['RelatedEvent'] = [r_event.get('Event') for r_event in event.get('RelatedEvent')]

        for i_event in misp_response:
            event = i_event['Event']
            misp_organisation = f"MISP.{event.get('orgc_name')}"
            dbot_score = get_dbot_level(event.get('threat_level_id'))
            # Build RelatedEvent
            # if dbot_score is suspicious or malicious
            dbot_obj = {
                'Indicator': file_hash,
                'Type': 'hash',
                'Vendor': 'MISP V2',
                'Score': dbot_score
            }

            file_obj = {
                hash_format: file_hash
            }
            # if malicious, find file with given hash
            if dbot_score == 3:
                file_obj['Malicious'] = {
                    'Vendor': 'MISP V2',
                    'Description': f'file hash found in MISP event with ID: {event.get("id")}'
                }

            md_obj = {
                'EventID': event.get('id'),
                'Threat Level': THREAT_LEVELS_WORDS[event.get('threat_level_id')],
                'Organisation': misp_organisation
            }

            file_list.append(file_obj)
            dbot_list.append(dbot_obj)
            md_list.append(md_obj)

        # Building entry
        outputs = {
            outputPaths.get('file'): file_list,
            outputPaths.get('dbotscore'): dbot_list
        }
        md = tableToMarkdown(f'Results found in MISP for hash: {file_hash}', md_list)

    else:
        md = f"No events found in MISP for hash {file_hash}"
        outputs = {
            outputPaths.get('dbotscore'): {
                'Indicator': file_hash,
                'Type': 'hash',
                'Vendor': 'MISP V2',
                'Score': Common.DBotScore.NONE,
            },
        }

    return_results(CommandResults(
        readable_output=md,
        outputs=outputs,
        raw_response=misp_response,
    ))


def get_ips_events():
    ips = argToList(demisto.args().get('ip'), ',')
    for ip in ips:
        check_ip(ip)


def check_ip(ip):
    """
    Gets a IP and returning its reputation (if exists)
    ip (str): IP to check
    """
    if not is_ip_valid(ip):
        return_error("IP isn't valid")

    misp_response = MISP.search(value=ip)

    if misp_response:
        dbot_list = list()
        ip_list = list()
        md_list = list()

        for event_in_response in misp_response:
            event = event_in_response.get('Event')
            dbot_score = get_dbot_level(event.get('threat_level_id'))
            misp_organisation = f'MISP.{event.get("Orgc").get("name")}'

            dbot_obj = {
                'Indicator': ip,
                'Type': 'ip',
                'Vendor': 'MISP V2',
                'Score': dbot_score
            }
            ip_obj = {'Address': ip}
            # if malicious
            if dbot_score == 3:
                ip_obj['Malicious'] = {
                    'Vendor': 'MISP V2',
                    'Description': f'IP Found in MISP event: {event.get("id")}'
                }
            md_obj = {
                'EventID': event.get('id'),
                'Threat Level': THREAT_LEVELS_WORDS[event.get('threat_level_id')],
                'Organisation': misp_organisation
            }

            ip_list.append(ip_obj)
            dbot_list.append(dbot_obj)
            md_list.append(md_obj)

        outputs = {
            outputPaths.get('ip'): ip_list,
            outputPaths.get('dbotscore'): dbot_list,
            MISP_PATH: build_context(misp_response)
        }
        md = tableToMarkdown(f'Results found in MISP for IP: {ip}', md_list)

    else:
        md = f'No events found in MISP for IP: {ip}'
        outputs = {
            outputPaths.get('dbotscore'): {
                'Indicator': ip,
                'Type': DBotScoreType.IP,
                'Vendor': 'MISP V2',
                'Score': Common.DBotScore.NONE,
            },
        }

    return_results(CommandResults(
        readable_output=md,
        outputs=outputs,
        raw_response=misp_response,
    ))


def get_time_now():
    """
    Returns:
    str: time in year--month--day format
    """
    time_now = time.gmtime(time.time())
    return f'{time_now.tm_year}--{time_now.tm_mon}--{time_now.tm_mday}'


def get_new_event(args):
    event = MISPEvent()
    event.distribution = args.get('distribution')
    threat_level_id_arg = args.get('threat_level_id')
    event.threat_level_id = THREAT_LEVELS_NUMBERS[
        threat_level_id_arg] if threat_level_id_arg in THREAT_LEVELS_NUMBERS else threat_level_id_arg
    analysis_arg = args.get('analysis')
    event.analysis = ANALYSIS_NUMBERS.get(analysis_arg) if analysis_arg in ANALYSIS_NUMBERS else analysis_arg

    event.info = args.get('info') if args.get('info') else 'Event from Demisto'
    event.date = args.get('date') if args.get('date') else get_time_now()
    event.published = argToBoolean(args.get('published', 'False'))
    event.orgc_id = args.get('orgc_id')
    event.org_id = args.get('org_id')
    event.sharing_group_id = args.get('sharing_group_id')

    return event


def create_event(pymisp: ExpandedPyMISP, demisto_args: dict, ret_only_event_id: bool = False,
                 data_keys_to_save: list = []) -> Union[int, None]:
    """Creating event in MISP with the given attribute

    Args:
        pymisp
        demisto_args
        ret_only_event_id (bool): returning event ID if set to True
        data_keys_to_save

    Returns:
        int: event_id
    """
    new_event = get_new_event(demisto_args)
    new_event = pymisp.add_event(new_event, True)
    event_id = get_valid_event_id(new_event.id)
    if ret_only_event_id:
        return event_id

    add_attribute(event_id=event_id, internal=True, pymisp=pymisp, data_keys_to_save=data_keys_to_save,
                  new_event=new_event, demisto_args=demisto_args)
    event = pymisp.search(eventid=event_id)

    human_readable = f"## MISP create event\nNew event with ID: {event_id} has been successfully created.\n"

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='MISP.Event',
        outputs_key_field='id',
        outputs=build_context(event, data_keys_to_save),
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


def add_attribute(pymisp: ExpandedPyMISP, event_id: int = None, internal: bool = False, demisto_args: dict = {},
                  data_keys_to_save: list = [], new_event: MISPEvent = None):
    """Adding attribute to a given event
    This function can be called as an independence command or as part of another command (create event for example)

    Args:
        event_id (int): Event ID to add attribute to
        internal (bool): if set to True, will not post results to Demisto
        demisto_args (dict): Demisto args
        pymisp(ExpandedPyMISP):
        data_keys_to_save (list):
    """
    attributes_args = {
        'id': demisto_args.get('id'),  # misp event id
        'type': demisto_args.get('type', 'Other'),
        'category': demisto_args.get('category'),
        'to_ids': argToBoolean(demisto_args.get('to_ids', True)),
        'comment': demisto_args.get('comment'),
        'value': demisto_args.get('value')
    }
    attributes_args.update({'id': get_valid_event_id(event_id)}) if event_id else None
    distribution = demisto_args.get('distribution')
    attributes_args.update({'distribution': get_valid_distribution(distribution)}) if distribution else None

    if not new_event:
        new_event = pymisp.search(eventid=attributes_args.get('id'), pythonify=True)[0]

    new_event.add_attribute(**attributes_args)
    pymisp.update_event(event=new_event)
    if internal:
        return

    updated_event = pymisp.search(eventid=attributes_args.get('id'))
    human_readable = f"## MISP add attribute\nNew attribute: {attributes_args.get('value')} " \
                     f"was added to event id {attributes_args.get('id')}.\n"

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='MISP.Event',
        outputs_key_field='id',
        outputs=build_context(updated_event, data_keys_to_save),
    )


def download_samples(pymisp: ExpandedPyMISP, sample_hash=None, event_id=None, all_samples=False):
    to_post = {'request': {'hash': sample_hash, 'eventID': event_id, 'allSamples': all_samples}}
    response = pymisp._prepare_request('POST', urljoin(pymisp.root_url, 'attributes/downloadSample'),
                                       data=json.dumps(to_post))
    result = pymisp._check_response(response)
    if result.get('error') is not None:
        return False, result.get('error')
    if not result.get('result'):
        return False, result.get('message')
    details = []
    for f in result['result']:
        decoded = base64.b64decode(f['base64'])
        zipped = BytesIO(decoded)
        try:
            archive = zipfile.ZipFile(zipped)
            if f.get('md5'):
                # New format
                unzipped = BytesIO(archive.open(f['md5'], pwd=b'infected').read())
            else:
                # Old format
                unzipped = BytesIO(archive.open(f['filename'], pwd=b'infected').read())
            details.append([f['event_id'], f['filename'], unzipped])
        except zipfile.BadZipfile:
            # In case the sample isn't zipped
            details.append([f['event_id'], f['filename'], zipped])

    return True, details


def download_file(pymisp: ExpandedPyMISP, demisto_args: dict):
    """
    Will post results of given file's hash if present.
    MISP's response should be in case of success:
        (True, [EventID, filename, fileContent])
    in case of failure:
        (False, 'No hits with the given parameters.')
    """
    file_hash = demisto_args.get('hash')
    event_id = demisto_args.get('eventID')
    unzip = argToBoolean(demisto_args.get('unzip', 'False'))
    all_samples = True if demisto_args.get('allSamples') in ('1', 'true') else False

    response = download_samples(pymisp=pymisp, sample_hash=file_hash, event_id=event_id, all_samples=all_samples)
    if not response[0]:
        return CommandResults(readable_output=f"Couldn't find file with hash {file_hash}")
    else:
        if unzip:
            files = list()
            for f in response:
                # Check if it's tuple. if so, f = (EventID, hash, fileContent)
                if isinstance(f, tuple) and len(f) == 3:
                    filename = f[1]
                    files.append(fileResult(filename, f[2].getbuffer()))
            return files
        else:
            file_buffer = response[1][0][2].getbuffer()
            filename = response[1][0][1]
            return fileResult(filename, file_buffer)


def get_urls_events():
    urls = argToList(demisto.args().get('url'), ',')
    demisto.results(urls)
    for url in urls:
        check_url(url)


def check_url(url):
    response = MISP.search(value=url, type_attribute='url')

    if response:
        dbot_list = list()
        md_list = list()
        url_list = list()

        for event_in_response in response:
            event = event_in_response.get('Event')
            dbot_score = get_dbot_level(event.get('threat_level_id'))
            misp_organisation = f"MISP.{event.get('Orgc').get('name')}"

            dbot_obj = {
                'Indicator': url,
                'Type': 'url',
                'Vendor': 'MISP V2',
                'Score': dbot_score
            }

            url_obj = {
                'Data': url,
            }
            if dbot_score == 3:
                url_obj['Malicious'] = {
                    'Vendor': 'MISP V2',
                    'Description': f'IP Found in MISP event: {event.get("id")}'
                }
            md_obj = {
                'EventID': event.get('id'),
                'Threat Level': THREAT_LEVELS_WORDS[event.get('threat_level_id')],
                'Organisation': misp_organisation
            }
            dbot_list.append(dbot_obj)
            md_list.append(md_obj)
            url_list.append(url_obj)
        outputs = {
            outputPaths.get('url'): url_list,
            outputPaths.get('dbotscore'): dbot_list,
            MISP_PATH: build_context(response)
        }
        md = tableToMarkdown(f'MISP Reputation for URL: {url}', md_list)

    else:
        md = f'No events found in MISP for URL: {url}'
        outputs = {
            outputPaths.get('dbotscore'): {
                'Indicator': url,
                'Type': DBotScoreType.URL,
                'Vendor': 'MISP V2',
                'Score': Common.DBotScore.NONE,
            },
        }

    return_results(CommandResults(
        readable_output=md,
        outputs=outputs,
        raw_response=response,
    ))


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
        misp_complex_query = MISP.build_complex_query(**misp_query_params)
        return misp_complex_query

    return demisto_query


def search(post_to_warroom: bool = True) -> Tuple[dict, Any]:
    """
    will search in MISP
    Returns
     dict: Object with results to demisto:
    """
    d_args = demisto.args()
    # List of all applicable search arguments
    search_args = [
        'event_id',
        'value',
        'type',
        'category',
        'org',
        'tags',
        'from',
        'to',
        'last',
        'eventid',
        'uuid',
        'to_ids'
    ]

    args = dict()
    # Create dict to pass into the search
    for arg in search_args:
        if arg in d_args:
            args[arg] = d_args[arg]
    # Replacing keys and values from Demisto to Misp's keys
    if 'type' in args:
        args['type_attribute'] = d_args.pop('type')
    # search function 'to_ids' parameter gets 0 or 1 instead of bool.
    if 'to_ids' in args:
        args['to_ids'] = 1 if d_args.get('to_ids') in ('true', '1', 1) else 0
    # build MISP complex filter
    if 'tags' in args:
        args['tags'] = build_misp_complex_filter(args['tags'])

    response = MISP.search(**args)
    if response:
        response_for_context = build_context(response)

        # Prepare MD. getting all keys and values if exists
        args_for_md = {key: value for key, value in args.items() if value}
        if post_to_warroom:
            md = tableToMarkdown('Results in MISP for search:', args_for_md)
            md_event = response_for_context[0]
            md += f'Total of {len(response_for_context)} events found\n'
            event_highlights = {
                'Info': md_event.get('Info'),
                'Timestamp': convert_timestamp(md_event.get('Timestamp')),
                'Analysis': ANALYSIS_WORDS[md_event.get('Analysis')],
                'Threat Level ID': THREAT_LEVELS_WORDS[md_event.get('ThreatLevelID')],
                'Event Creator Email': md_event.get('EventCreatorEmail'),
                'Attributes': json.dumps(md_event.get('Attribute'), indent=4),
                'Related Events': md_event.get('RelatedEvent')
            }
            md += tableToMarkdown(f'Event ID: {md_event.get("ID")}', event_highlights)
            if md_event.get('Galaxy'):
                md += tableToMarkdown('Galaxy:', md_event.get('Galaxy'))

            demisto.results({
                'Type': entryTypes['note'],
                'Contents': response,
                'ContentsFormat': formats['json'],
                'HumanReadable': md,
                'ReadableContentsFormat': formats['markdown'],
                'EntryContext': {
                    MISP_PATH: response_for_context
                }
            })
        return response_for_context, response
    else:
        demisto.results(f"No events found in MISP for {args}")
        return {}, {}


def search_attributes() -> Tuple[dict, Any]:
    """
    Execute a MIPS search using the 'attributes' controller.
    """
    d_args = demisto.args()
    # List of all applicable search arguments
    search_args = [
        'value',
        'type',
        'category',
        'uuid',
        'to_ids',
        'last',
        'include_decay_score'
    ]
    args = dict()
    # Create dict to pass into the search
    for arg in search_args:
        if arg in d_args:
            args[arg] = d_args[arg]
    # Replacing keys and values from Demisto to Misp's keys
    if 'type' in args:
        args['type_attribute'] = d_args.pop('type')
    # search function 'to_ids' parameter gets 0 or 1 instead of bool.
    if 'to_ids' in args:
        args['to_ids'] = 1 if d_args.get('to_ids') in ('true', '1', 1) else 0
    if 'include_decay_score' in args:
        args['includeDecayScore'] = 1 if d_args.get('include_decay_score') in ('true', '1', 1) else 0

    # Set the controller to attributes to search for attributes and not events
    args['controller'] = 'attributes'

    response = MISP.search(**args)

    if response:
        response_for_context = build_attribute_context(copy.deepcopy(response))

        md = f'## MISP attributes-search returned {len(response_for_context)} attributes.\n'

        # if attributes were returned, display one to the warroom to visualize the result:
        if len(response_for_context) > 0:
            md += tableToMarkdown(f'Attribute ID: {response_for_context[0].get("ID")}', response_for_context[0])

        demisto.results({
            'Type': entryTypes['note'],
            'Contents': response,
            'ContentsFormat': formats['json'],
            'HumanReadable': md,
            'ReadableContentsFormat': formats['markdown'],
            'EntryContext': {
                MISP_ATTRIBUTE_PATH: response_for_context
            }
        })
        return response_for_context, response
    else:
        demisto.results(f"No attributes found in MISP for {args}")
        return {}, {}


def delete_event(pymisp: ExpandedPyMISP, demisto_args: dict):
    """
    Gets an event id and deletes it.
    """
    event_id = demisto_args.get('event_id')
    event = pymisp.delete_event(event_id)
    if 'errors' in event:
        return_error(f'Event ID: {event_id} has not found in MISP: \nError message: {event}')
    else:
        human_readable = f'Event {event_id} has been deleted'
        return CommandResults(readable_output=human_readable)


def add_tag(pymisp: ExpandedPyMISP, demisto_args: dict, data_keys_to_save: list = []):
    """
    Function will add tag to given UUID of event or attribute.
    """
    uuid = demisto_args.get('uuid')
    tag = demisto_args.get('tag')

    pymisp.tag(uuid, tag)
    event = pymisp.search(uuid=uuid)
    human_readable = f'Tag {tag} has been successfully added to event {uuid}'

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='MISP.Event',
        outputs_key_field='ID',
        outputs=build_context(event, data_keys_to_save),
    )


def add_sighting(pymisp: ExpandedPyMISP, demisto_args: dict):
    """Adds sighting to MISP attribute

    """
    attribute_id = demisto_args.get('id')
    attribute_uuid = demisto_args.get('uuid')
    attribute_type = demisto_args['type']  # mandatory arg
    att_id = attribute_id or attribute_uuid
    if not att_id:
        return_error('ID or UUID not specified')

    sighting_args = {
        'id': attribute_id,
        'uuid': attribute_uuid,
        'type': SIGHTING_MAP[attribute_type]
    }
    sigh_obj = MISPSighting()
    sigh_obj.from_dict(**sighting_args)
    pymisp.add_sighting(sigh_obj, att_id)

    human_readable = f'Sighting \'{attribute_type}\' has been successfully added to attribute {att_id}'
    return CommandResults(readable_output=human_readable)


def test(pymisp: ExpandedPyMISP):
    """
    Test module.
    """
    response = pymisp._prepare_request('GET', 'servers/getPyMISPVersion.json')
    if pymisp._check_json_response(response):
        return 'ok'
    else:
        return_error('MISP has not connected.')


def add_events_from_feed(pymisp: ExpandedPyMISP, demisto_args: dict, use_ssl: bool, proxies: dict):
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
            event = pymisp.add_event(e)
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


def add_object(event_id: str, obj: MISPObject, pymisp: ExpandedPyMISP):
    """Sending object to MISP and returning outputs

    Args:
        obj: object to add to MISP
        event_id: ID of event
        pymisp:
    """
    response = pymisp.add_object(event_id, misp_object=obj)
    if 'errors' in response:
        errors = extract_error(response["errors"])
        error_string = str()
        for err in errors:
            error_string += f'\n\tError code: {err["code"]} ' \
                            f'\n\tMessage: {err["message"]}' \
                            f'\n\tErrors: {err["errors"]}\n'
        return_error(f'Error in `{demisto.command()}` command: {error_string}')
    for ref in obj.ObjectReference:
        response = pymisp.add_object_reference(ref)

    formatted_response = replace_keys(response)
    formatted_response.update({"ID": event_id})

    human_readable = f'Object has been added to MISP event ID {event_id}'
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='MISP.Event',
        outputs_key_field='ID',
        outputs=formatted_response,
    )


def add_email_object(pymisp: ExpandedPyMISP, demisto_args: dict = {}):
    entry_id = demisto_args.get('entry_id')
    event_id = demisto_args.get('event_id')
    email_path = demisto.getFilePath(entry_id).get('path')
    obj = FileObject(email_path)
    return add_object(event_id, obj, pymisp)


def add_domain_object(pymisp: ExpandedPyMISP, demisto_args: dict = {}):
    """Adds a domain object to MISP
    domain-ip description: https://www.misp-project.org/objects.html#_domain_ip
    """
    args = ['text', 'creation_date', 'first_seen', 'last_seen']
    event_id = demisto_args.get('event_id')
    domain = demisto_args.get('name')
    obj = MISPObject('domain-ip')
    ips = argToList(demisto_args.get('dns'))
    for ip in ips:
        obj.add_attribute('ip', value=ip)
    obj.add_attribute('domain', value=domain)
    for arg in args:
        value = demisto_args.get(arg)
        if value:
            obj.add_attribute(arg, value=value)
    return add_object(event_id, obj, pymisp)


def add_file_object(pymisp: ExpandedPyMISP, demisto_args: dict = {}):
    """Adds a file object to MISP

    """
    args = ['text', 'creation_date', 'first_seen', 'last_seen']
    event_id = demisto_args.get('event_id')
    file_encoding = demisto_args.get('file_encoding')
    file_name = demisto_args.get('filename')
    full_path = demisto_args.get('full_path')
    md5 = demisto_args.get('md5')
    mimetype = demisto_args.get('mimetype')
    sha1 = demisto_args.get('sha1')
    sha256 = demisto_args.get('sha256')
    size = demisto_args.get('size')
    state = demisto_args.get('state')
    text = demisto_args.get('text')
    obj = MISPObject('file')
    obj.add_attribute('file', value=domain)
    for arg in args:
        value = demisto_args.get(arg)
        if value:
            obj.add_attribute(arg, value=value)
    return add_object(event_id, obj, pymisp)


def add_url_object(pymisp: ExpandedPyMISP, demisto_args: dict = {}):
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
    url_obj = [
        {'url': url}
    ]

    url_obj.append({'scheme': url_parse.scheme}) if url_parse.scheme else None
    url_obj.append({'resource_path': url_parse.path}) if url_parse.path else None
    url_obj.append({'query_string': url_parse.query}) if url_parse.query else None
    url_obj.append({'domain': url_parse.netloc}) if url_parse.netloc else None
    url_obj.append({'fragment': url_parse.fragment}) if url_parse.fragment else None
    url_obj.append({'port': url_parse.port}) if url_parse.port else None
    url_obj.append(
        {'credential': (url_parse.username, url_parse.password)}) if url_parse.username and url_parse.password else None

    for arg in url_args:
        user_arg = demisto_args.get(arg)
        if user_arg:
            url_obj.append({arg.replace('_', '-'): user_arg})

    g_object = build_generic_object('url', url_obj)
    return add_object(event_id, g_object, pymisp)


def add_generic_object_command(pymisp: ExpandedPyMISP, demisto_args: dict = {}):
    event_id = demisto_args.get('event_id')
    template = demisto_args.get('template')
    attributes = demisto_args.get('attributes').replace("'", '"')
    try:
        args = json.loads(attributes)
        if not isinstance(args, list):
            args = build_list_from_dict(args)
        obj = build_generic_object(template, args)
        return add_object(event_id, obj, pymisp)
    except ValueError as e:
        return_error(f'`attribute` parameter could not be decoded, may not a valid JSON\nattribute: {attributes}',
                     str(e))


def add_ip_object(pymisp: ExpandedPyMISP, demisto_args: dict = {}):
    # todo split into sub-functions
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
    misp_attributes_args = [{arg.replace('_', '-'): demisto_args.get(arg)} for arg in args if demisto_args.get(arg)]
    ips = argToList(demisto_args.get('ip'))
    for ip in ips:
        misp_attributes_args.append({'ip': ip})
    if misp_attributes_args:
        non_req_args = [
            'first_seen',
            'last_seen',
        ]
        misp_attributes_args.extend(
            {arg.replace('_', '-'): demisto_args.get(arg)} for arg in non_req_args if demisto_args.get(arg))
        if demisto_args.get('comment'):
            misp_attributes_args.append({'text': demisto_args.get('comment')})
        obj = build_generic_object('ip-port', misp_attributes_args)
        return add_object(event_id, obj, pymisp)
    else:
        return_error(f'None of required arguments presents. command {demisto.command()} requires one of {args}')


def main():
    params = demisto.params()
    verify = not params.get('insecure')
    proxies = handle_proxy()  # type: ignore

    misp_api_key = params.get('api_key')
    misp_url = params.get('url')

    pymisp = ExpandedPyMISP(url=misp_url, key=misp_api_key, ssl=verify, proxies=proxies)  # type: ExpandedPyMISP

    data_keys_to_save = argToList(params.get('context_select', []))

    MAX_ATTRIBUTES = params.get('attributes_limit', 1000)
    try:
        MAX_ATTRIBUTES = int(MAX_ATTRIBUTES)
    except ValueError:
        return_error("Maximum attributes in event must be a positive and a valid number")

    if MAX_ATTRIBUTES < 1:
        return_error("Maximum attributes in event must be a positive number")

    command = demisto.command()

    demisto.debug(f'MISP V3: command is {command}')

    try:
        args = demisto.args()
        if command == 'test-module':
            return_results(test(pymisp=pymisp))  # checked V
        elif command == 'misp-download-sample':
            return_results(download_file(demisto_args=args, pymisp=pymisp))  # checked V
        elif command == 'misp-create-event':
            return_results(create_event(demisto_args=args, pymisp=pymisp, data_keys_to_save=data_keys_to_save))
            # checked V
        elif command == 'misp-add-attribute':
            return_results(
                add_attribute(demisto_args=args, pymisp=pymisp, data_keys_to_save=data_keys_to_save))  # checked V
        elif command == 'misp-search':
            search()
        elif command == 'misp-search-attributes':
            search_attributes()
        elif command == 'misp-delete-event':
            return_results(delete_event(demisto_args=args, pymisp=pymisp))  # checked
        elif command == 'misp-add-sighting':
            return_results(add_sighting(demisto_args=args, pymisp=pymisp))  # checked V
        elif command == 'misp-add-tag':
            return_results(add_tag(demisto_args=args, pymisp=pymisp, data_keys_to_save=data_keys_to_save))  # checked V
        elif command == 'misp-add-events-from-feed':
            return_results(
                add_events_from_feed(demisto_args=args, pymisp=pymisp, use_ssl=verify, proxies=proxies))  # checked V
        elif command == 'file':
            get_files_events()
        elif command == 'url':
            get_urls_events()
        elif command == 'ip':
            get_ips_events()
        #  Object commands
        elif command == 'misp-add-email-object':
            return_results(add_email_object(demisto_args=args, pymisp=pymisp))  # checked V
        elif command == 'misp-add-domain-object':
            return_results(add_domain_object(demisto_args=args, pymisp=pymisp))  # checked V
        elif command == 'misp-add-url-object':
            return_results(add_url_object(demisto_args=args, pymisp=pymisp))  # checked V
        elif command == 'misp-add-ip-object':
            return_results(add_ip_object(demisto_args=args, pymisp=pymisp))  # checked V - split into sub-funcs
        elif command == 'misp-add-object':
            return_results(add_generic_object_command(demisto_args=args, pymisp=pymisp))  # checked V
        elif command == 'misp-add-file-object':
            return_results(add_file_object(demisto_args=args, pymisp=pymisp))  # checked
    except PyMISPError as e:
        return_error(e.message)
    except Exception as e:
        return_error(str(e))


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
