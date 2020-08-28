import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import json


class Client(BaseClient):

    def __init__(self, base_url, *args, **kwarg):
        super().__init__(base_url, *args, **kwarg)


    def http_request(self, *args, **kwargs):
        """
        Wraps the CommonServerPython _http_request method
        Returns:
            Response content, can be: JSON, XML, or Text
        """
        r = self._http_request(*args, **kwargs)

        return r
        # else:
            # return_error(f'Unexpected response from service: {r}')


# Works
def test_module(client: Client):
    client.http_request('GET', 'users')

    return 'ok'


# Works
def query_samples(client, **args):
    params = {
        'subset': args.get('subset')
    }

    r = client.http_request('GET', 'samples', params=params)

    results = CommandResults(
        outputs_prefix = 'Triage.samples',
        outputs_key_field = 'data',
        outputs = r['data']
    )
    return results


# Works
#   - Need to add more parameters
def submit_sample(client: Client, **args):
    # url = f'{base_url}/samples'

    data = {
        # 'kind':'url', # Change this to use a command argument
        # 'interactive':'false',
        # 'profile':[]
        'kind': args.get('kind'),
        # 'interactive': (args.get('interactive', False)),
        'profile': args.get('profiles', [])
    }

    if data['kind'] == 'url':
        data.update({'url': args.get('data')})
        r = client.http_request('POST', 'samples', json_data=data)
    elif data['kind'] == 'file':

        file_path = demisto.getFilePath(demisto.args().get('data')).get('path')
        with open(file_path, 'rb') as f:
            files = {
                'file': f,
                '_json': (None, '{"kind":"file","interactive":false}')
            }

            r = client.http_request('POST', 'samples', json_data=data, files=files)
    else:
        return_error(f'Type of sample needs to be selected, either "file" or "url", the selected type was: {data["kind"]}')

    results = CommandResults(
        outputs_prefix = 'Triage.submissions',
        outputs_key_field = 'data',
        outputs = r
    )
    return results

# Works
def get_sample(client: Client, **args):
    sample_id = args.get("sample_id")
    r = client.http_request('GET', f'samples/{sample_id}')

    results = CommandResults(
        outputs_prefix = 'Triage.samples',
        outputs_key_field = 'data',
        outputs = r
    )
    return results


# def get_sample_status(client: Client, **args):
#     # Avoid using this endpoint where possible per docs
#     pass

# Works
def get_sample_summary(client: Client, **args):
    sample_id = args.get('sample_id')
    r = client.http_request('GET', f'samples/{sample_id}/summary')

    results = CommandResults(
        outputs_prefix = 'Triage.sample.summaries',
        outputs_key_field = 'data',
        outputs = r
    )
    return results


# Works
def delete_sample(client: Client, **args):
    sample_id=args.get('sample_id')
    client.http_request('DELETE', f'samples/{sample_id}')

    return f'Sample {sample_id} successfully deleted'


# Works
#   - Basic auto works, test more with picking and specifying profile
def set_sample_profile(client: Client, **args):
    '''
    Used to move a submitted sample from static analysis to behavioural by giving it a profile to run under
    '''
    sample_id = args.get('sample_id')

    data = {
        'auto': argToBoolean(args.get('auto', True)),
        'pick': argToList(args.get('pick', []))
    }
    if args.get('profiles'):
        data.update({'profiles': [{'profile': args.get('profiles', '')}]})
    data = json.dumps(data)

    client.http_request('POST', f'samples/{sample_id}/profile', data=data)

    return f'Profile successfully set for sample {sample_id}'


# Works
def get_static_report(client: Client, **args):
    '''
    Get's the static analysis report from a given sample
    '''
    sample_id=args.get('sample_id')

    r = client.http_request('GET', f'samples/{sample_id}/reports/static')

    results = CommandResults(
        outputs_prefix = 'Triage.sample.reports.static',
        outputs_key_field = 'data',
        outputs = r
    )

    return results


# Works
def get_report_triage(client: Client, **args):
    '''
    Works
    Outputs a score, should map to a DBot score
    '''
    sample_id=args.get('sample_id')
    task_id=args.get('task_id')

    r = client.http_request('GET', f'samples/{sample_id}/{task_id}/report_triage.json')

    results = CommandResults(
        outputs_prefix = 'Triage.sample.reports.triage',
        outputs_key_field = 'data',
        outputs = r
    )

    return results


# FAILING
# def get_sample_events(client: Client, **args):
#     '''
#     Need to test
#     '''
#     sample_id=args.get('sample_id')
#
#     # This will continue to have events available to pull until the status = reported / failed
#     while True:
#         r = client.http_request('GET', f'samples/{sample_id}/events')
#
#         results = CommandResults(
#             outputs_prefix = 'Triage.sample.events',
#             outputs_key_field = 'data',
#             outputs = r
#         )
#
#         # If status indicates completion, return to break the loop, else print to WarRoom and continue loop
#         if r.get('status') in ['reported', 'failed']:
#             return results
#         else:
#             return_results(results)
#             time.sleep(5)


# FAILING
# Can probably combine this with the above sample events
# def get_all_sample_events(client: Client, **args):
#     '''
#     Need to test
#     '''
#     sample_id=args.get('sample_id')
#
#     # This will continue to have events available to pull until the status = reported / failed
#     while True:
#         r = client.http_request('GET', f'samples/events')
#
#         results = CommandResults(
#             outputs_prefix = 'Triage.sample.events',
#             outputs_key_field = 'data',
#             outputs = r
#         )
#
#         # If status indicates completion, return to break the loop, else print to WarRoom and continue loop
#         if r.get('status') in ['reported', 'failed']:
#             return results
#         else:
#             return_results(results)


# Working
#   - Need to update readable_output
def get_kernel_monitor(client: Client, **args):
    '''
    Need to test
    '''
    sample_id=args.get('sample_id')
    task_id=args.get('task_id')

    r = client.http_request('GET', f'samples/{sample_id}/{task_id}/logs/onemon.json', resp_type='text')

    res = []
    for x in r.split('\n'):
        try:
            res.append(json.loads(x))
        except json.decoder.JSONDecodeError:
            return_results(f'Error parsing: {x}')
            continue

    results = CommandResults(
        outputs_prefix = 'Triage.sample.kernel_monitor',
        outputs_key_field = 'data',
        outputs = res,
        readable_output = 'testing'
    )

    return results


# Works
def get_pcap(client: Client, **args):
    '''
    Works
    '''
    sample_id = args.get('sample_id')
    task_id = args.get('task_id')

    r = client.http_request('GET', f'samples/{sample_id}/{task_id}/dump.pcap', resp_type='response')

    filename = f'{sample_id}.pcap'
    file_content = r.content

    return fileResult(filename, file_content)


# ??
def get_dumped_files(client: Client, **args):
    '''
    Need to test
        - Need to upload a sample that will have a file to dump, maybe an installer e.g. msi?
    '''
    sample_id=args.get('sample_id')
    task_id=args.get('task_id')
    file_name=args.get('file_name')

    r = client.http_request('GET', f'samples/{sample_id}/{task_id}/files/{file_name}')

    results = CommandResults(
        outputs_prefix = 'Triage.sample.file_dump',
        outputs_key_field = 'data',
        outputs = r
    )

    return results


# Working
def get_users(client: Client, **args):
    '''
    Works
    '''
    if args.get('userID'):
        url_suffix = f'users/{args.get("userID")}'
    else:
        url_suffix = f'users'

    r = client.http_request('GET', url_suffix)

    # Depending on the api endpoint used, the results are either in the 'data' key or not
    if r.get('data'):
        r = r['data']

    results = CommandResults(
        outputs_prefix = 'Triage.users',
        outputs_key_field = 'data',
        outputs = r
    )

    return results



# Working
def create_user(client: Client, **args):
    '''
    Works
    '''

    # Make the following data variable parameters
    data = {
        "username": args.get('username'),
        "first_name": args.get('firstName', 'XSOAR'),
        "last_name": args.get('lastName', 'Bot'),
        "password": args.get('password', 'changeme1234'),  # Can this be replaced with /sensitive_input command?
        "permissions": argToList(args.get('permissions', ['view_samples', 'submit_samples'])) # ["view_samples","submit_samples","access_api"]    # Need to make this a selectable list, find out all available permissions
    }

    data = json.dumps(data)

    r = client.http_request('POST', 'users', data=data)

    results = CommandResults(
        outputs_prefix = 'Triage.users',
        outputs_key_field = 'data',
        outputs = r
    )

    return results



# Working
def delete_user(client: Client, **args):
    '''
    Works
    '''

    userID = args.get('userID')

    r = client.http_request('DELETE', f'users/{userID}')

    results = CommandResults(
        outputs_prefix = 'Triage.users',
        outputs_key_field = 'data',
        outputs = r,
        readable_output = 'User successfully deleted'
    )

    return results



# Working
def create_apikey(client: Client, **args):
    '''
    - Check the formatting of the output once instance UI is working better
    - Note: It seems you can't create an API key for yourself through the API
    '''
    userID = args.get('userID')
    name = args.get('name', 'Created from XSOAR')

    data = json.dumps({
        'name': name
    })

    r = client.http_request('POST', f'users/{userID}/apikeys', data=data)

    results = CommandResults(
        outputs_prefix = 'Triage.apikey',
        outputs_key_field = 'data',
        outputs = r
    )

    return results


# Working
def get_apikey(client: Client, **args):
    '''
    - Check the formatting of the output once instance UI is working better
    '''
    userID = args.get('userID')
    r = client.http_request('GET', f'users/{userID}/apikeys')

    results = CommandResults(
        outputs_prefix = 'Triage.apikey',
        outputs_key_field = 'data',
        outputs = r
    )

    return results


# Working
def delete_apikey(client: Client, **args):
    '''
    Working
    '''
    userID = args.get('userID')
    apiKeyName = args.get('apiKeyName', 'Created from XSOAR')

    r = client.http_request('DELETE', f'users/{userID}/apikeys/{apiKeyName}')

    results = CommandResults(
        outputs_prefix = 'Triage.apikey',
        outputs_key_field = 'data',
        outputs = r,
        readable_output = f'API key {apiKeyName} was successfully deleted'
    )
    return results


# Working
def get_profile(client: Client, **args):
    '''
    - Need to check the UI for results formatting
    '''

    profileID = args.get('profileID')

    if profileID:
        url_suffix = f'profiles/{profileID}'
    else:
        url_suffix = f'profiles'

    r = client.http_request('GET', url_suffix)

    if not profileID:
        r = r['data']

    results = CommandResults(
        outputs_prefix = 'Triage.profiles',
        outputs_key_field = 'data',
        outputs = r
    )
    return results



# Working
def create_profile(client: Client, **args):

    data = json.dumps({
        "name": args.get('name'),
        "tags": argToList(args.get('tags')),
        "timeout": int(args.get('timeout', 120)),
        "network": args.get('network'),
        "browser": args.get('browser')
    })

    r = client.http_request('POST', f'profiles', data=data)

    results = CommandResults(
        outputs_prefix = 'Triage.profiles',
        outputs_key_field = 'data',
        outputs = r
    )

    return results


# Working
def update_profile(client: Client, **args):
    '''
    Working, but should test with more parameters
    '''
    profileID = args.get('profileID')

    data = {}

    for arg in args:
        if arg in ['name', 'tags', 'timeout']:
            if arg == 'timeout':
                data[arg] = int(args.get(arg))
            else:
                data[arg] = args.get(arg)

    r = client.http_request('PUT', f'profiles/{profileID}', data=json.dumps(data))

    results = CommandResults(
        outputs_prefix = 'Triage.profiles',
        outputs_key_field = 'data',
        outputs = r,
        readable_output = 'Profile updated successfully'
    )
    return results


# Working
def delete_profile(client: Client, **args):
    '''
    Working
    '''

    profileID = args.get('profileID')

    r = client.http_request('DELETE', f'profiles/{profileID}')

    results = CommandResults(
        outputs_prefix = 'Triage.profiles',
        outputs_key_field = 'data',
        outputs = r,
        readable_output = 'Profile successfully deleted'
    )
    return results


def main():
    params = demisto.params()
    args = demisto.args()
    client = Client(
        params.get('base_url'),
        verify = params.get('Verify SSL'),
        headers={'Authorization': f'Bearer {params.get("API Key")}'}
    )

    commands = {
        'test-module': test_module,
        'triage-query-samples': query_samples,
        'triage-submit-sample': submit_sample,
        'triage-get-sample': get_sample,
        'triage-get-sample-summary': get_sample_summary,
        'triage-delete-sample': delete_sample,
        # Add in the rest of the commands, already coded, just add in and test
        'triage-set-sample-profile': set_sample_profile,
        'triage-get-static-report': get_static_report,
        'triage-get-report-triage': get_report_triage,
        # 'triage-get-sample-events': get_sample_events,
        # 'triage-get-all-sample-events': get_all_sample_events,
        'triage-get-kernel-monitor': get_kernel_monitor,
        'triage-get-pcap': get_pcap,
        'triage-get-dumped-files': get_dumped_files,
        'triage-get-users': get_users,
        'triage-create-user': create_user,
        'triage-delete-user': delete_user,
        'triage-create-api-key': create_apikey,
        'triage-get-api-key': get_apikey,
        'triage-delete-api-key': delete_apikey,
        'triage-get-profiles': get_profile,
        'triage-create-profile': create_profile,
        'triage-update-profile': update_profile,
        'triage-delete-profile': delete_profile
    }

    command = demisto.command()
    if command in commands:
        return_results(commands[command](client, **args))
    else:
        return_error(f'Command {command} is not available in this integration')


if __name__ in ['__main__','__builtin__','builtins']:
    main()
