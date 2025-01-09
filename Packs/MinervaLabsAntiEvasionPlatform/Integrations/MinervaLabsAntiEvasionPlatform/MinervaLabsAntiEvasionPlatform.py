import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' IMPORTS '''
import json
import urllib3
import requests

# Disable insecure warnings
urllib3.disable_warnings()


''' GLOBALS '''
USERNAME = demisto.params().get('credentials').get('identifier')
PASSWORD = demisto.params().get('credentials').get('password')
BASE_URL = demisto.params().get('url')
VERIFY_SSL = not demisto.params().get('insecure', False)


''' HELPERS '''


def get_session():
    session = requests.Session()
    session.verify = VERIFY_SSL
    return session


def create_entry_context(context_id, data):
    ec = {}
    if context_id.endswith('processes'):
        context = []
        for process in data:
            process_context = {
                'Endpoint': process['endpoint'],
                'SHA256': process['fileHash'],
                'CommandLine': process['processCommandLine'],
                'Username': process['username'],
                'CreateTime': process['startTime'],
                'Pid': process['processId'],
                'Name': process['processName']
            }
            context.append(process_context)
        ec['Minerva.Process(val.Id === obj.Id)'] = context
    elif context_id.endswith('endpoints'):
        context = []
        for endpoint in data:
            endpoint_context = {
                'Group': endpoint['group'],
                'Name': endpoint['endpoint'],
                'Users': endpoint['loggedOnUsers'],
                'IP': endpoint['reportedIpAddress'],
                'OS': endpoint['operatingSystem']
            }
            context.append(endpoint_context)
        ec['Minerva.Endpoint(val.Id === obj.Id)'] = context
    elif context_id.endswith('groups'):
        context = []
        for group in data:
            group_context = {
                'Name': group['name'],
                'Id': group['id'],
                'Policy': group['policy'],
                'PolicyVersion': group['policyVersion'],
                'SimulationStatus': group['endpointSettings'],
                'Endpoints': group['endpoints'],
                'CreationTime': group['creationTime']
            }
            context.append(group_context)
        ec['Minerva.Group(val.Id === obj.Id)'] = context
    elif context_id.endswith('vaccination'):
        context = []
        if isinstance(data, list):
            for vaccine in data:
                vaccine_context = {
                    'Id': vaccine['id'],
                    'Name': vaccine['name'],
                    'Type': vaccine['type'],
                    'Description': vaccine['description'],
                    "IsMonitorOnly": vaccine['isMonitorOnly'],
                    'Last modified by': vaccine['lastModifiedBy'],
                    'Last modified on': vaccine['lastModifiedOn']
                }
                context.append(vaccine_context)
            ec['Minerva.Vaccine(val.Id === obj.Id)'] = context
        else:
            context = [{
                'Id': data['id'],
                'Name': data['name'],
                'Type': data['type'],
                'Description': data['description'],
                "IsMonitorOnly": data['isMonitorOnly'],
                'Last modified by': data['lastModifiedBy'],
                'Last modified on': data['lastModifiedOn']
            }]
            ec['Minerva.Vaccine(val.Id === obj.Id)'] = context
    elif context_id.endswith('exclusions'):
        context = []
        if isinstance(data, list):
            for exclusion in data:
                exclusion_context = {
                    'Id': exclusion['id'],
                    'Type': exclusion['type'],
                    'Exclusion data': exclusion['data'],
                    'Description': exclusion['description'],
                    'Last modified by': exclusion['lastModifiedBy'],
                    'Last modified on': exclusion['lastModifiedOn'],
                    'Applied groups': exclusion['appliedGroupsIds']
                }
                context.append(exclusion_context)
            ec['Minerva.Exclusion(val.Id === obj.Id)'] = context
        else:
            context = [{
                'Id': data['id'],
                'Type': data['type'],
                'Exclusion data': data['data'],
                'Description': data['description'],
                'Last modified by': data['lastModifiedBy'],
                'Last modified on': data['lastModifiedOn'],
                'Applied groups': data['appliedGroupsIds']
            }]
            ec['Minerva.Exclusion(val.Id === obj.Id)'] = context
    else:
        demisto.debug(f'Failed to create entry context for {context_id}')

    return ec


''' FUNCTIONS '''


def get_from_url(url):
    url_text = url.split('/')[-1]
    response = session.get(url)
    if response.status_code != 200:
        return_error(f'Error while fetching {url_text}. More information: {response.status_code}, {response.reason}')

    if not response.json():
        return {
            'Type': entryTypes['note'],
            'ContentsFormat': formats['markdown'],
            'Contents': f'No contents retrieved for {url_text}'
        }

    return {
        'Type': entryTypes['note'],
        'ContentsFormat': formats['markdown'],
        'Contents': response.json(),
        'HumanReadable': tableToMarkdown(pascalToSpace(url_text), response.json(),
                                         headerTransform=pascalToSpace, removeNull=True),
        'EntryContext': create_entry_context(url_text, response.json())
    }


@logger
def login():
    return session.post(f'{BASE_URL}/api/login',
                        json={'username': USERNAME,
                              'password': PASSWORD})


@logger
def logout():
    session.post(f'{BASE_URL}/api/login/logout')


def fetch_incidents():
    try:
        r_events = session.post(f'{BASE_URL}/api/events',
                                json={"archive": False})
        if r_events.status_code != 200:
            raise Exception(f'Error in API call. More information: {r_events.status_code}, {r_events.reason}')

        incidents = []
        for event in r_events.json():
            incident = {
                'name': f'Minerva Labs Event - {event["type"]}',
                'rawJSON': json.dumps(event)
            }
            incidents.append(incident)
            session.put(f'{BASE_URL}/api/events/archive',
                        json={'events': event['id']})
        demisto.incidents(incidents)
    except Exception as e:
        return_error(f'Error while fetching incidents. More information: {e}')


@logger
def get_groups():
    get_groups_url = f'{BASE_URL}/api/groups'
    response = session.get(get_groups_url, params={'_limit': '1000'})
    if response.status_code != 200 or not response.json():
        return_error(f'Error while fetching groups. More information: {response.status_code}, {response.reason}')

    results = {
        'Type': entryTypes['note'],
        'ContentsFormat': formats['markdown'],
        'Contents': response.json(),
        'HumanReadable': tableToMarkdown('Available groups', t=response.json(), headerTransform=pascalToSpace, removeNull=True),
        'EntryContext': create_entry_context(get_groups_url, response.json())
    }
    demisto.results(results)


@logger
def add_exclusion(exclusion_type, exclusion_data, exclusion_description, groups_id):
    groups_ids_list = [group_id.strip() for group_id in groups_id.split(',')]
    json_params = {
        'type': exclusion_type,
        'description': exclusion_description,
        'data': exclusion_data,
        'appliedGroupsIds': groups_ids_list
    }
    exclusions_url = f'{BASE_URL}/api/exclusions'
    response = session.post(exclusions_url, json=json_params)
    if response.status_code == 409 and response.reason == 'Conflict':
        demisto.results('Exclusion already exists')
        return
    if response.status_code != 200:
        return_error(f'Error while adding exclusion. More information: {response.status_code}, {response.reason}')

    results = {
        'Type': entryTypes['note'],
        'ContentsFormat': formats['markdown'],
        'Contents': response.json(),
        'HumanReadable': tableToMarkdown(f'Exclusion \'{exclusion_description}\' was added', response.json(),
                                         headerTransform=pascalToSpace, removeNull=True),
        'EntryContext': create_entry_context(exclusions_url, response.json())
    }

    demisto.results(results)


@logger
def get_exclusions():
    results = get_from_url(f'{BASE_URL}/api/exclusions')
    demisto.results(results)


@logger
def delete_exclusion(exclusion_id, exclusion_type):
    json_params = {
        'id': exclusion_id,
        'type': exclusion_type
    }
    response = session.post(f'{BASE_URL}/api/exclusions/delete', json=[json_params])
    if response.status_code != 200:
        return_error(f'Error while deleting exclusions. More information: {response.status_code}, {response.reason}')
    demisto.results(f'Exclusion {exclusion_id} was deleted')


@logger
def add_vaccine(vaccine_name, vaccine_desc, monitor_only):
    json_params = {'name': vaccine_name,
                   'description': vaccine_desc,
                   'isMonitorOnly': monitor_only,
                   'type': 'mutex'}
    vaccination_url = f'{BASE_URL}/api/vaccination'
    response = session.post(vaccination_url, json=json_params)
    if response.status_code == 409 and response.reason == 'Conflict':
        demisto.results('Vaccination already exists')
        return
    if response.status_code != 200:
        return_error(f'Error while adding a vaccine. More information: {response.status_code}, {response.reason}')

    results = {
        'Type': entryTypes['note'],
        'ContentsFormat': formats['markdown'],
        'Contents': response.json(),
        'HumanReadable': tableToMarkdown(f'Vaccination \'{vaccine_desc}\' was added', response.json(),
                                         headerTransform=pascalToSpace, removeNull=True)
    }

    if response.json():
        results['EntryContext'] = create_entry_context(vaccination_url, response.json())

    demisto.results(results)


@logger
def get_vaccines():
    results = get_from_url(f'{BASE_URL}/api/vaccination')
    demisto.results(results)


@logger
def delete_vaccines(vaccine_id):
    response = session.delete(f'{BASE_URL}/api/vaccination', params={'ids': [vaccine_id]})
    if response.status_code == 404:
        demisto.results(f'Vaccination with id {vaccine_id} was not found')
        return
    if response.status_code != 200:
        return_error(f'Error while deleting vaccination id: {vaccine_id}. More information: {response.status_code},\
                     {response.reason}')
    demisto.results(f'Vaccine \'{vaccine_id}\' was deleted')


@logger
def search(search_url, search_param, search_condition, search_value):
    json_params = {'filters': [{'param': search_param,
                                'condition': search_condition,
                                'value': search_value}]}
    response = session.post(search_url,
                            json=json_params)
    if response.status_code != 200:
        return_error(f'Error while perfroming search for\
                     {search_url.rsplit("/")[1]}. More information: {response.status_code}, {response.reason}')

    results = {
        'Type': entryTypes['note'],
        'ContentsFormat': formats['markdown'],
        'Contents': response.json(),
        'HumanReadable': tableToMarkdown(f'Search results for \'{search_url.split("/")[-1]}\'', response.json(),
                                         headerTransform=pascalToSpace, removeNull=True),
        'EntryContext': create_entry_context(search_url, response.json())
    }

    demisto.results(results)


@logger
def unarchive_events():
    response = session.put(f'{BASE_URL}/api/events/archive', json={'shouldArchive': False})
    if response.status_code != 200:
        return_error(f'Error while un-archiving events. More information: {response.status_code}, {response.reason}')
    demisto.results('Events were un-archived')


''' EXECUTION '''
session = get_session()
try:
    handle_proxy()

    args = demisto.args()

    def add_exclusion_command():
        exclusion_type = args.get('type')
        exclusion_data = args.get('data')
        exclusion_description = args.get('description')
        groups_id = args.get('appliedGroupsIds')
        add_exclusion(exclusion_type, exclusion_data, exclusion_description, groups_id)

    def delete_exclusion_command():
        exclusion_id = args.get('id')
        exclusion_type = args.get('type')
        delete_exclusion(exclusion_id, exclusion_type)

    def add_vaccine_command():
        vaccine_name = args.get('name')
        vaccine_desc = args.get('description')
        monitor_only = args.get('isMonitorOnly')
        add_vaccine(vaccine_name, vaccine_desc, monitor_only)

    def delete_vaccines_command():
        vaccine_id = args.get('vaccine_id')
        delete_vaccines(vaccine_id)

    def search_process_command():
        processes_search_url = f'{BASE_URL}/api/processes'
        search_param = args.get('param')
        search_condition = args.get('condition')
        search_value = args.get('value')
        search(processes_search_url, search_param, search_condition, search_value)

    def search_endpoint_command():
        endpoint_search_url = f'{BASE_URL}/api/endpoints'
        search_param = args.get('param')
        search_condition = args.get('condition')
        search_value = args.get('value')
        search(endpoint_search_url, search_param, search_condition, search_value)

    def get_groups_command():
        get_groups()

    demisto.debug(f'Command is {demisto.command()}')
    if USERNAME and PASSWORD:
        minerva_login = login()
    else:
        return_error('Failed to log in, no credentials were given')
    if demisto.command() == 'fetch-incidents':
        fetch_incidents()
    elif demisto.command() == 'test-module':
        if minerva_login.status_code == 200:  # pylint: disable=E0606
            demisto.results('ok')
        else:
            return_error(f'Failed to log in. More information: {minerva_login.status_code}, {minerva_login.reason}')
    elif demisto.command() == 'minerva-add-exclusion':
        add_exclusion_command()
    elif demisto.command() == 'minerva-get-exclusions':
        get_exclusions()
    elif demisto.command() == 'minerva-delete-exclusion':
        delete_exclusion_command()
    elif demisto.command() == 'minerva-add-vaccine':
        add_vaccine_command()
    elif demisto.command() == 'minerva-get-vaccines':
        get_vaccines()
    elif demisto.command() == 'minerva-delete-vaccine':
        delete_vaccines_command()
    elif demisto.command() == 'minerva-search-process':
        search_process_command()
    elif demisto.command() == 'minerva-search-endpoint':
        search_endpoint_command()
    elif demisto.command() == 'minerva-get-groups':
        get_groups_command()
    elif demisto.command() == 'minerva-unarchive-events':
        unarchive_events()
except Exception as e:
    demisto.debug(f'Cannot perform the command: {demisto.command()}. Error: {e}')
    return_error(e)
finally:
    logout()
