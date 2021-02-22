# type: ignore

import logging
import warnings
from typing import Union, List, Any, Tuple, Dict
from urllib.parse import urlparse

import requests
from pymisp import ExpandedPyMISP, PyMISPError, MISPObject
from pymisp.tools import EMailObject, GenericObjectGenerator

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
MISP_KEY = demisto.params().get('api_key')
MISP_URL = demisto.params().get('url')
USE_SSL = not demisto.params().get('insecure')
proxies = handle_proxy()  # type: ignore
MISP_PATH = 'MISP.Event(obj.ID === val.ID)'
MISP = ExpandedPyMISP(url=MISP_URL, key=MISP_KEY, ssl=USE_SSL, proxies=proxies)  # type: ExpandedPyMISP
DATA_KEYS_TO_SAVE = demisto.params().get('context_select', [])

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
    'meta-category': 'MetaCategory'
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


def remove_unselected_context_keys(context_data):
    for attribute in context_data['Attribute']:
        for key in list(attribute.keys()):
            if key not in DATA_KEYS_TO_SAVE:
                del attribute[key]


def arrange_context_according_to_user_selection(context_data):
    if not DATA_KEYS_TO_SAVE:
        return

    # each related event has it's own attributes
    for event in context_data:
        # Remove attributes om event
        remove_unselected_context_keys(event)
        # Remove attributes in Objects
        for obj in event['Object']:
            remove_unselected_context_keys(obj)


def build_context(response: Union[dict, requests.Response]) -> dict:  # type: ignore
    """
    Gets a MISP's response and building it to be in context. If missing key, will return the one written.

    Args:
       response (requests.Response or dict):
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
    arrange_context_according_to_user_selection(events)  # type: ignore
    return events  # type: ignore


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
                'Vendor': misp_organisation,
                'Score': dbot_score
            }

            file_obj = {
                hash_format: file_hash
            }
            # if malicious, find file with given hash
            if dbot_score == 3:
                file_obj['Malicious'] = {
                    'Vendor': misp_organisation,
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
        ec = {
            outputPaths.get('file'): file_list,
            outputPaths.get('dbotscore'): dbot_list
        }

        md = tableToMarkdown(f'Results found in MISP for hash: {file_hash}', md_list)

        demisto.results({
            'Type': entryTypes['note'],
            'Contents': misp_response,
            'ContentsFormat': formats['json'],
            'HumanReadable': md,
            'ReadableContentsFormat': formats['markdown'],
            'EntryContext': ec
        })
    else:
        demisto.results(f"No events found in MISP for hash {file_hash}")


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
                'Vendor': misp_organisation,
                'Score': dbot_score
            }
            ip_obj = {'Address': ip}
            # if malicious
            if dbot_score == 3:
                ip_obj['Malicious'] = {
                    'Vendor': misp_organisation,
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

        ec = {
            outputPaths.get('ip'): ip_list,
            outputPaths.get('dbotscore'): dbot_list,
            MISP_PATH: build_context(misp_response)
        }

        md = tableToMarkdown(f'Results found in MISP for IP: {ip}', md_list)
        demisto.results({
            'Type': entryTypes['note'],
            'Contents': misp_response,
            'ContentsFormat': formats['json'],
            'HumanReadable': md,
            'ReadableContentsFormat': formats['markdown'],
            'EntryContext': ec
        })
    else:
        demisto.results(f'No events found in MISP for IP: {ip}')


def upload_sample():
    """
    Misp needs to get files in base64. in the old integration (js) it was converted by a script.
    """
    # Creating dict with Demisto's arguments
    args = ['distribution', 'to_ids', 'category', 'info', 'analysis', 'comment', 'threat_level_id']
    args = {key: demisto.args().get(key) for key in args if demisto.args().get(key)}
    args['threat_level_id'] = THREAT_LEVELS_NUMBERS.get(demisto.args().get('threat_level_id')) if demisto.args().get(
        'threat_level_id') in THREAT_LEVELS_NUMBERS else demisto.args().get('threat_level_id')
    args['analysis'] = ANALYSIS_NUMBERS.get(demisto.args().get('analysis')) if demisto.args().get(
        'analysis') in ANALYSIS_NUMBERS else demisto.args().get('analysis')
    event_id = demisto.args().get('event_id')

    file = demisto.getFilePath(demisto.args().get('fileEntryID'))
    filename = file.get('name')
    file = file.get('path')

    if not file:
        return_error(f'file {filename} is empty or missing')

    if not event_id:
        if not demisto.args().get('info'):
            demisto.args()['info'] = filename
        event_id = create_event(ret_only_event_id=True)

    res = MISP.upload_sample(filename=filename, filepath_or_bytes=file, event_id=event_id, **args)
    if res.get('name') == 'Failed':
        ec = None
    else:
        ec = {"MISP.UploadedSample": {filename: event_id}}
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': res,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable':
            f"MISP upload sample \n* message: {res.get('message')}\n* event id: {event_id}\n* file name: {filename}",
        'EntryContext': ec,
    })


def get_time_now():
    """
    Returns:
    str: time in year--month--day format
    """
    time_now = time.gmtime(time.time())
    return f'{time_now.tm_year}--{time_now.tm_mon}--{time_now.tm_mday}'


def create_event(ret_only_event_id: bool = False) -> Union[int, None]:
    """Creating event in MISP with the given attribute

    Args:
        ret_only_event_id (bool): returning event ID if set to True

    Returns:
        int: event_id
    """
    d_args = demisto.args()
    # new_event in the old integration gets some args that belongs to attribute, so after creating the basic event,
    # we will add attribute
    event_dic = {
        'distribution': d_args.get('distribution'),
        'threat_level_id': THREAT_LEVELS_NUMBERS.get(d_args.get('threat_level_id')) if d_args.get(
            'threat_level_id') in THREAT_LEVELS_NUMBERS else d_args.get('threat_level_id'),
        'analysis': ANALYSIS_NUMBERS.get(demisto.args().get('analysis')) if demisto.args().get(
            'analysis') in ANALYSIS_NUMBERS else demisto.args().get('analysis'),
        'info': d_args.get('info') if d_args.get('info') else 'Event from Demisto',
        'date': d_args.get('date') if d_args.get('date') else get_time_now(),
        'published': True if d_args.get('published') == 'true' else False,
        'orgc_id': d_args.get('orgc_id'),
        'org_id': d_args.get('org_id'),
        'sharing_group_id': d_args.get('sharing_group_id')
    }

    event = MISP.new_event(**event_dic)
    event_id = event.get('id')
    if isinstance(event_id, str) and event_id.isdigit():
        event_id = int(event_id)
    elif not isinstance(event_id, int):
        return_error('EventID must be a number')

    if ret_only_event_id:
        return event_id

    # add attribute
    add_attribute(event_id=event_id, internal=True)

    event = MISP.search(eventid=event_id)

    md = f"## MISP create event\nNew event with ID: {event_id} has been successfully created.\n"
    ec = {
        MISP_PATH: build_context(event)
    }

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': event,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': md,
        'EntryContext': ec
    })
    return None


def add_attribute(event_id: int = None, internal: bool = None):
    """Adding attribute to given event

    Args:
        event_id (int): Event ID to add attribute to
        internal(bool): if set to True, will not post results to Demisto
    """
    d_args = demisto.args()
    args = {
        'id': d_args.get('id'),
        'type': d_args.get('type') if d_args.get('type') else 'other',
        'category': d_args.get('category'),
        'to_ids': True if d_args.get('to_ids') == 'true' else False,
        'distribution': d_args.get('distribution'),
        'comment': d_args.get('comment'),
        'value': d_args.get('value')
    }
    if event_id:
        args['id'] = event_id  # type: ignore
    if isinstance(args.get('id'), str) and args.get('id').isdigit():  # type: ignore
        args['id'] = int(args['id'])
    elif not isinstance(args.get('id'), int):
        return_error('Invalid MISP event ID, must be a number')
    if args.get('distribution') is not None:
        if not isinstance(args.get('distribution'), int):
            if isinstance(args.get('distribution'), str) and args.get('distribution').isdigit():  # type: ignore
                args['distribution'] = int(args['distribution'])
            elif isinstance(args.get('distribution'), str) and args['distribution'] in DISTRIBUTION_NUMBERS:
                args['distribution'] = DISTRIBUTION_NUMBERS.get(args['distribution'])
            else:
                return_error(
                    "Distribution can be 'Your_organisation_only', "
                    "'This_community_only', 'Connected_communities' or 'All_communities'"
                )

    event = MISP.get_event(args.get('id'))

    # add attributes
    event.add_attribute(**args)
    MISP.update_event(event=event)
    if internal:
        return
    event = MISP.search(eventid=args.get('id'))
    md = f"## MISP add attribute\nNew attribute: {args.get('value')} was added to event id {args.get('id')}.\n"
    ec = {
        MISP_PATH: build_context(event)
    }
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': {},
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': md,
        'EntryContext': ec
    })


def download_file():
    """
    Will post results of given file's hash if present.
    MISP's response should be in case of success:
        (True, [EventID, filename, fileContent])
    in case of failure:
        (False, 'No hits with the given parameters.')
    """
    file_hash = demisto.args().get('hash')
    event_id = demisto.args().get('eventID')
    unzip = True if demisto.args().get('unzip') == 'true' else False
    all_samples = True if demisto.args().get('allSamples') in ('1', 'true') else False

    response = MISP.download_samples(sample_hash=file_hash,
                                     event_id=event_id,
                                     all_samples=all_samples,
                                     unzip=unzip
                                     )
    if not response[0]:
        demisto.results(f"Couldn't find file with hash {file_hash}")
    else:
        if unzip:
            files = list()
            for f in response:
                # Check if it's tuple. if so, f = (EventID, hash, fileContent)
                if isinstance(f, tuple) and len(f) == 3:
                    filename = f[1]
                    files.append(fileResult(filename, f[2].getbuffer()))
            demisto.results(files)
        else:
            file_buffer = response[1][0][2].getbuffer()
            filename = response[1][0][1]
        demisto.results(fileResult(filename, file_buffer))  # type: ignore


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
                'Vendor': misp_organisation,
                'Score': dbot_score
            }

            url_obj = {
                'Data': url,
            }
            if dbot_score == 3:
                url_obj['Malicious'] = {
                    'Vendor': misp_organisation,
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
        ec = {
            outputPaths.get('url'): url_list,
            outputPaths.get('dbotscore'): dbot_list,
            MISP_PATH: build_context(response)
        }
        md = tableToMarkdown(f'MISP Reputation for URL: {url}', md_list)
        demisto.results({
            'Type': entryTypes['note'],
            'Contents': response,
            'ContentsFormat': formats['json'],
            'HumanReadable': md,
            'ReadableContentsFormat': formats['markdown'],
            'EntryContext': ec
        })
    else:
        demisto.results(f'No events found in MISP for URL: {url}')


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


def delete_event():
    """
    Gets an event id and deletes it.
    """
    event_id = demisto.args().get('event_id')
    event = MISP.delete_event(event_id)
    if 'errors' in event:
        return_error(f'Event ID: {event_id} has not found in MISP: \nError message: {event}')
    else:
        md = f'Event {event_id} has been deleted'
        demisto.results({
            'Type': entryTypes['note'],
            'Contents': event,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': md
        })


def add_tag():
    """
    Function will add tag to given UUID of event or attribute.
    """
    uuid = demisto.args().get('uuid')
    tag = demisto.args().get('tag')

    MISP.tag(uuid, tag)
    event = MISP.search(uuid=uuid)
    ec = {
        MISP_PATH: build_context(event)
    }
    md = f'Tag {tag} has been successfully added to event {uuid}'
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': event,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': md,
        'EntryContext': ec
    })


def add_sighting():
    """Adds sighting to MISP attribute

    """
    sighting = {
        'sighting': 0,
        'false_positive': 1,
        'expiration': 2
    }
    kargs = {
        'id': demisto.args().get('id'),
        'uuid': demisto.args().get('uuid'),
        'type': sighting.get(demisto.args().get('type'))
    }
    att_id = demisto.args().get('id', demisto.args().get('uuid'))
    if att_id:
        MISP.set_sightings(kargs)
        demisto.results(f'Sighting \'{demisto.args().get("type")}\' has been successfully added to attribute {att_id}')
    else:
        return_error('ID or UUID not specified')


def test():
    """
    Test module.
    """
    if MISP.test_connection():
        demisto.results('ok')
    else:
        return_error('MISP has not connected.')


def add_events_from_feed():
    """Gets an OSINT feed from url and publishing them to MISP
    urls with feeds for example: `https://www.misp-project.org/feeds/`
    feed format must be MISP.
    """
    headers = {'Accept': 'application/json'}
    url = demisto.getArg('feed')  # type: str
    url = url[:-1] if url.endswith('/') else url
    if PREDEFINED_FEEDS.get(url):
        url = PREDEFINED_FEEDS[url].get('url')  # type: ignore
    limit = demisto.getArg('limit')  # type: str
    limit_int = int(limit) if limit.isdigit() else 0

    osint_url = f'{url}/manifest.json'
    not_added_counter = 0
    try:
        uri_list = requests.get(osint_url, verify=USE_SSL, headers=headers, proxies=proxies).json()
        events_numbers = list()  # type: List[Dict[str, int]]
        for num, uri in enumerate(uri_list, 1):
            req = requests.get(f'{url}/{uri}.json', verify=USE_SSL, headers=headers, proxies=proxies).json()
            event = MISP.add_event(req)
            if 'id' in event:
                events_numbers.append({'ID': event['id']})
            else:
                not_added_counter += 1
            # If limit exists
            if limit_int == num:
                break

        entry_context = {MISP_PATH: events_numbers}
        human_readable = tableToMarkdown(
            f'Total of {len(events_numbers)} events was added to MISP.',
            events_numbers,
            headers='Event IDs'
        )
        if not_added_counter:
            human_readable = f'{human_readable}\n' \
                             f'{not_added_counter} events were not added. Might already been added earlier.'

        return_outputs(human_readable, outputs=entry_context)
    except ValueError:
        return_error(f'URL [{url}] is not a valid MISP feed')


def add_object(event_id: str, obj: MISPObject):
    """Sending object to MISP and returning outputs

    Args:
        obj: object to add to MISP
        event_id: ID of event
    """
    response = MISP.add_object(event_id, misp_object=obj)
    if 'errors' in response:
        errors = extract_error(response["errors"])
        error_string = str()
        for err in errors:
            error_string += f'\n\tError code: {err["code"]} ' \
                            f'\n\tMessage: {err["message"]}' \
                            f'\n\tErrors: {err["errors"]}\n'
        return_error(f'Error in `{command}` command: {error_string}')
    for ref in obj.ObjectReference:
        response = MISP.add_object_reference(ref)
    formatted_response = replace_keys(response)
    entry_context = {
        MISP_PATH:
            {
                'ID': event_id
            }
    }
    entry_context[MISP_PATH].update(formatted_response)  # type: ignore
    human_readable = f'Object has been added to MISP event ID {event_id}'

    return_outputs(
        human_readable,
        entry_context,
        response
    )  # type: ignore


def add_email_object():
    entry_id = demisto.getArg('entry_id')
    event_id = demisto.getArg('event_id')
    email_path = demisto.getFilePath(entry_id).get('path')
    obj = EMailObject(email_path)
    add_object(event_id, obj)


def add_domain_object():
    """Adds a domain object to MISP
    domain-ip description: https://www.misp-project.org/objects.html#_domain_ip
    """
    template = 'domain-ip'
    args = [
        'text',
        'creation_date',
        'first_seen',
        'last_seen'
    ]
    event_id = demisto.getArg('event_id')
    domain = demisto.getArg('name')
    obj = MISPObject(template)
    ips = argToList(demisto.getArg('dns'))
    for ip in ips:
        obj.add_attribute('ip', value=ip)
    obj.add_attribute('domain', value=domain)
    for arg in args:
        value = demisto.getArg(arg)
        if value:
            obj.add_attribute(arg, value=value)
    add_object(event_id, obj)


def add_url_object():
    """Building url object in MISP scheme
    Scheme described https://www.misp-project.org/objects.html#_url
    """
    template = 'url'
    url_args = [
        'text',
        'last_seen',
        'first_seen'
    ]
    event_id = demisto.getArg('event_id')
    url = demisto.getArg('url')
    url_parse = urlparse(url)
    url_obj = [
        {'url': url}
    ]
    if url_parse.scheme:
        url_obj.append({'scheme': url_parse.scheme})
    if url_parse.path:
        url_obj.append({'resource_path': url_parse.path})
    if url_parse.query:
        url_obj.append({'query_string': url_parse.query})
    if url_parse.netloc:
        url_obj.append({'domain': url_parse.netloc})
    if url_parse.fragment:
        url_obj.append({'fragment': url_parse.fragment})
    if url_parse.port:
        url_obj.append({'port': url_parse.port})
    if url_parse.username and url_parse.password:
        url_obj.append({'credential': (url_parse.username, url_parse.password)})
    for arg in url_args:
        new_arg = demisto.getArg(arg)
        if new_arg:
            url_obj.append({arg.replace('_', '-'): new_arg})

    g_object = build_generic_object(template, url_obj)
    add_object(event_id, g_object)


def add_generic_object_command():
    event_id = demisto.getArg('event_id')
    template = demisto.getArg('template')
    attributes = demisto.getArg('attributes')  # type: str
    attributes = attributes.replace("'", '"')
    try:
        args = json.loads(attributes)
        if not isinstance(args, list):
            args = build_list_from_dict(args)
        obj = build_generic_object(template, args)
        add_object(event_id, obj)
    except ValueError as e:
        return_error(f'`attribute` parameter could not be decoded, may not a valid JSON\nattribute: {attributes}',
                     str(e))


def add_ip_object():
    template = 'ip-port'
    event_id = demisto.getArg('event_id')
    args = [
        'dst_port',
        'src_port',
        'domain',
        'hostname',
        'ip_src',
        'ip_dst'
    ]
    attr = [{arg.replace('_', '-'): demisto.getArg(arg)} for arg in args if demisto.getArg(arg)]
    ips = argToList(demisto.getArg('ip'))
    for ip in ips:
        attr.append({'ip': ip})
    if attr:
        non_req_args = [
            'first_seen',
            'last_seen',
        ]
        attr.extend({arg.replace('_', '-'): demisto.getArg(arg)} for arg in non_req_args if demisto.getArg(arg))
        if demisto.getArg('comment'):
            attr.append({'text': demisto.getArg('comment')})
        obj = build_generic_object(template, attr)
        add_object(event_id, obj)
    else:
        return_error(f'None of required arguments presents. command {command} requires one of {args}')


''' COMMANDS MANAGER / SWITCH PANEL '''
command = demisto.command()


def main():
    LOG(f'command is {command}')

    demisto.info(f'command is {command}')
    try:
        if command == 'test-module':
            #  This is the call made when pressing the integration test button.
            test()
        elif command == 'misp-upload-sample':
            upload_sample()
        elif command == 'misp-download-sample':
            download_file()
        elif command in ('internal-misp-create-event', 'misp-create-event'):
            create_event()
        elif command in ('internal-misp-add-attribute', 'misp-add-attribute'):
            add_attribute()
        elif command == 'misp-search':
            search()
        elif command == 'misp-delete-event':
            delete_event()
        elif command == 'misp-add-sighting':
            add_sighting()
        elif command == 'misp-add-tag':
            add_tag()
        elif command == 'misp-add-events-from-feed':
            add_events_from_feed()
        elif command == 'file':
            get_files_events()
        elif command == 'url':
            get_urls_events()
        elif command == 'ip':
            get_ips_events()
        #  Object commands
        elif command == 'misp-add-email-object':
            add_email_object()
        elif command == 'misp-add-domain-object':
            add_domain_object()
        elif command == 'misp-add-url-object':
            add_url_object()
        elif command == 'misp-add-ip-object':
            add_ip_object()
        elif command == 'misp-add-object':
            add_generic_object_command()
    except PyMISPError as e:
        return_error(e.message)
    except Exception as e:
        return_error(str(e))


if __name__ in ('__builtin__', 'builtins'):
    main()

# TODO: in 5.0
#   * Add !file (need docker change).
