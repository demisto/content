import requests

params = demisto.params()
args = demisto.args()

base_url = params.get('URL').strip('/')

api_key = params.get('API Key')
headers = {
    'Authorization': f'Bearer {api_key}'
}



def http_req():
    pass


def test_module():
    url = f'{base_url}/users'
    r = requests.get(url, headers=headers)
    if r.ok:
        return_results('ok')
    else:
        return_results(f'Status Code: {r.status_code}\nBody: {r.text}')


def query_samples():
    url = f'{base_url}/samples'

    params = {
        'subset': args.get('subset')
    }

    r = requests.get(url, headers=headers, params=params)

    if r.ok:
        # return_results(r.json())
        # md = tableToMarkdown('Samples', [r.json()]) # built-in to CommandResults
        # return_results(r.json())
        results = CommandResults(
            outputs_prefix = 'Triage.samples',
            outputs_key_field = 'data',
            outputs = r.json()['data']
            # outputs = r.json()
        )
        return_results(results)
    else:
        return_error(f'Status Code: {r.status_code}\nResponse Body: {r.text}')


def submit_sample():
    url = f'{base_url}/samples'

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
        r = requests.post(url, headers=headers, json=data)
    elif data['kind'] == 'file':

        file_path = demisto.getFilePath(demisto.args().get('data')).get('path')
        with open(file_path, 'rb') as f:
            # TODO: Add in optional file name
            files = {
                'file': f,
                '_json': (None, '{"kind":"file","interactive":false}')
            }

            r = requests.post(url, headers=headers, json=data, files=files)
    else:
        return_error(f'Type of sample needs to be selected, either "file" or "url", the selected type was: {data["kind"]}')

    if r.ok:
        # return_results(r.json())
        results = CommandResults(
            outputs_prefix = 'Triage.submissions',
            outputs_key_field = 'data',
            # outputs = r.json()['data']
            outputs = r.json()
        )
        return_results(results)
    else:
        return_error(f'Status Code: {r.status_code}\nResponse Body: {r.text}')


def get_sample(sample_id=args.get('sample_id')):
    url = f'{base_url}/samples/{sample_id}'

    r = requests.get(url, headers=headers)

    if r.ok:
        # return_results(r.json())
        results = CommandResults(
            outputs_prefix = 'Triage.samples',
            outputs_key_field = 'data',
            # outputs = r.json()['data']
            outputs = r.json()
        )
        return_results(results)
    else:
        return_error(f'Status Code: {r.status_code}\nResponse Body: {r.text}')


def get_sample_status():
    # Avoid using this endpoint where possible per docs
    pass


def get_sample_summary(sample_id=args.get('sample_id')):
    url = f'{base_url}/samples/{sample_id}/summary'

    r = requests.get(url, headers=headers)

    if r.ok:
        # return_results(r.json())
        results = CommandResults(
            outputs_prefix = 'Triage.sample.summaries',
            outputs_key_field = 'data',
            # outputs = r.json()['data']
            outputs = r.json()
        )
        return_results(results)
    else:
        return_error(f'Status Code: {r.status_code}\nResponse Body: {r.text}')


def delete_sample(sample_id=args.get('sample_id')):
    url = f'{base_url}/samples/{sample_id}'

    r = requests.delete(url, headers=headers)

    if r.ok:
        return_results(f'Sample {sample_id} successfully deleted')
    else:
        return_error(f'Status Code: {r.status_code}\nResponse Body: {r.text}')


def set_sample_profile(sample_id=args.get('sample_id')):
    '''
    Need to test
    '''
    url = f'{base_url}/samples/{sample_id}/profile'

    data = {
        'auto': args.get('auto', 'true'),
        'pick': args.get('pick', []),
        'profiles': args.get('profiles', [])
    }

    r = requests.post(url, headers=headers, data=data)

    if r.ok:
        return_results(r.json())
        return_results(f'Sample {sample_id} profile successfully set')
    else:
        return_error(f'Status Code: {r.status_code}\nResponse Body: {r.text}')


def get_static_report(sample_id=args.get('sample_id')):
    '''
    Need to test
    '''
    url = f'{base_url}/samples/{sample_id}/reports/static'

    r = requests.get(url, headers=headers)

    if r.ok:
        results = CommandResults(
            outputs_prefix = 'Triage.sample.reports',
            outputs_key_field = 'data',
            # outputs = r.json()['data']
            outputs = r.json()
        )
        return_results(results)
    else:
        return_error(f'Status Code: {r.status_code}\nResponse Body: {r.text}')


def get_triage_report(sample_id=args.get('sample_id'), task_id=args.get('task_id')):
    '''
    Need to test
    '''
    url = f'{base_url}/samples/{sample_id}/{task_id}/report_triage.json'

    r = requests.get(url, headers=headers)

    if r.ok:
        results = CommandResults(
            outputs_prefix = 'Triage.sample.reports',
            outputs_key_field = 'data',
            # outputs = r.json()['data']
            outputs = r.json()
        )
        return_results(results)
    else:
        return_error(f'Status Code: {r.status_code}\nResponse Body: {r.text}')


def get_sample_events(sample_id=args.get('sample_id')):
    '''
    Need to test
    '''
    url = f'{base_url}/samples/{sample_id}/events'

    while True:
        r = requests.get(url, headers=headers)
        data = r.json()

        if r.ok:
            results = CommandResults(
                outputs_prefix = 'Triage.sample.events',
                outputs_key_field = 'data',
                # outputs = r.json()['data']
                outputs = data
            )
            return_results(results)
        else:
            return_error(f'Status Code: {r.status_code}\nResponse Body: {r.text}')



def get_all_sample_events():
    '''
    Need to test
    '''
    url = f'{base_url}/samples/events'

    while True:
        r = requests.get(url, headers=headers)
        data = r.json()

        if r.ok:
            results = CommandResults(
                outputs_prefix = 'Triage.sample.events',
                outputs_key_field = 'data',
                # outputs = r.json()['data']
                outputs = data
            )
            return_results(results)
        else:
            return_error(f'Status Code: {r.status_code}\nResponse Body: {r.text}')


def get_kernel_monitor(sample_id=args.get('sample_id'), task_id=args.get('task_id')):
    '''
    Need to test
    '''
    url = f'{base_url}/samples/{sample_id}/{task_id}/logs/onemon.json'

    r = requests.get(url, headers=headers)

    if r.ok:
        results = CommandResults(
            outputs_prefix = 'Triage.sample.kernal_monitor',
            outputs_key_field = 'data',
            # outputs = r.json()['data']
            outputs = r.json()
        )
        return_results(results)
    else:
        return_error(f'Status Code: {r.status_code}\nResponse Body: {r.text}')


def get_pcap(sample_id=args.get('sample_id'), task_id=args.get('task_id')):
    '''
    Need to test
    '''
    url = f'{base_url}/samples/{sample_id}/{task_id}/dump.pcap'

    r = requests.get(url, headers=headers)

    if r.ok:
        results = CommandResults(
            outputs_prefix = 'Triage.sample.pcap',
            outputs_key_field = 'data',
            # outputs = r.json()['data']
            outputs = r.json()
        )
        return_results(results)
    else:
        return_error(f'Status Code: {r.status_code}\nResponse Body: {r.text}')


def get_dumped_files(sample_id=args.get('sample_id'), task_id=args.get('task_id'), file_name=args.get('file_name')):
    '''
    Need to test
    '''
    url = f'{base_url}/samples/{sample_id}/{task_id}/files/{file_name}'

    r = requests.get(url, headers=headers)

    if r.ok:
        results = CommandResults(
            outputs_prefix = 'Triage.sample.file_dump',
            outputs_key_field = 'data',
            # outputs = r.json()['data']
            outputs = r.json()
        )
        return_results(results)
    else:
        return_error(f'Status Code: {r.status_code}\nResponse Body: {r.text}')


class Users(BaseClient):

    def get_users(self, userID=None):
    '''
    Need to test
    '''
        if userID:
            url = f'{base_url}/users/{userID}'
        else:
            url = f'{base_url}/users'

        r = requests.post(url, headers=headers)

        if r.ok:
            results = CommandResults(
                outputs_prefix = 'Triage.users',
                outputs_key_field = 'data',
                # outputs = r.json()['data']
                outputs = r.json()
            )
            return_results(results)
        else:
            return_error(f'Status Code: {r.status_code}\nResponse Body: {r.text}')


    def create_user(self):
    '''
    Need to test
    '''
        url = f'{base_url}/users'

        # Make the following data variable parameters
        data = {
            "username": "foo",
            "first_name": "foo",
            "last_name": "bar",
            "password": "",
            "permissions":["view_samples","submit_samples","access_api"]    # Need to make this a selectable list, find out all available permissions
        }

        r = requests.post(url, headers=headers, data=data)
        if r.ok:
            results = CommandResults(
                outputs_prefix = 'Triage.users',
                outputs_key_field = 'data',
                # outputs = r.json()['data']
                outputs = r.json()
            )
            return_results(results)
        else:
            return_error(f'Status Code: {r.status_code}\nResponse Body: {r.text}')


    def delete_user(self):
    '''
    Need to test
    '''
        url = f'{base_url}/users/{userID}'

        r = requests.delete(url, headers=headers)

        if r.ok:
            results = CommandResults(
                outputs_prefix = 'Triage.users',
                outputs_key_field = 'data',
                # outputs = r.json()['data']
                outputs = r.json()
            )
            return_results(results)
        else:
            return_error(f'Status Code: {r.status_code}\nResponse Body: {r.text}')


    def create_apikey(self, userID=None, name='Created from XSOAR'):
    '''
    Need to test, should this be an included command?
    '''
        url = f'{base_url}/users/{userID}/apikeys'

        data = {
            'name': name
        }

        r = requests.post(url, headers=headers)

        if r.ok:
            results = CommandResults(
                outputs_prefix = 'Triage.apikey',
                outputs_key_field = 'data',
                # outputs = r.json()['data']
                outputs = r.json()
            )
            return_results(results)
        else:
            return_error(f'Status Code: {r.status_code}\nResponse Body: {r.text}')


    def get_apikey(self, userID=None):
    '''
    Need to test, should this be an included command?
    '''
        url = f'{base_url}/users/{userID}/apikeys'

        r = requests.get(url, headers=headers)

        if r.ok:
            results = CommandResults(
                outputs_prefix = 'Triage.apikey',
                outputs_key_field = 'data',
                # outputs = r.json()['data']
                outputs = r.json()
            )
            return_results(results)
        else:
            return_error(f'Status Code: {r.status_code}\nResponse Body: {r.text}')


    def delete_apikey(self, userID=None, apiKeyName=None):
    '''
    Need to test, should this be an included command?
    '''
        url = f'{base_url}/users/{userID}/apikeys/{apiKeyName}'

        r = requests.get(url, headers=headers)

        if r.ok:
            results = CommandResults(
                outputs_prefix = 'Triage.apikey',
                outputs_key_field = 'data',
                # outputs = r.json()['data']
                outputs = r.json()
            )
            return_results(results)
        else:
            return_error(f'Status Code: {r.status_code}\nResponse Body: {r.text}')


class Profiles(BaseClient):

    def get_profiles(self, profileID=None):
    '''
    Need to test
    '''
        if profileID:
            url = f'{base_url}/profiles/{profileID}'
        else:
            url = f'{base_url}/profiles'

        r = requests.get(url, headers=headers)

        if r.ok:
            results = CommandResults(
                outputs_prefix = 'Triage.profiles',
                outputs_key_field = 'data',
                # outputs = r.json()['data']
                outputs = r.json()
            )
            return_results(results)
        else:
            return_error(f'Status Code: {r.status_code}\nResponse Body: {r.text}')


    def create_profile(self):
    '''
    Need to test
    '''
        url = f'{base_url}/profiles'

        data = {
            "name":"foo",
            "tags":["foo","bar"],
            "timeout":120,
            "network":"internet"
        }

        r = requests.post(url, headers=headers, data=data)

        if r.ok:
            results = CommandResults(
                outputs_prefix = 'Triage.profiles',
                outputs_key_field = 'data',
                # outputs = r.json()['data']
                outputs = r.json()
            )
            return_results(results)
        else:
            return_error(f'Status Code: {r.status_code}\nResponse Body: {r.text}')


    def update_profile(self, profileID=None):
    '''
    Need to test
    '''
        url = f'{base_url}/profiles/{profileID}'

        data = {
            "name":"foo",
            "tags":["bar"],
            "timeout":120
        }

        r = requests.put(url, headers=headers, data=data)

        if r.ok:
            results = CommandResults(
                outputs_prefix = 'Triage.profiles',
                outputs_key_field = 'data',
                # outputs = r.json()['data']
                outputs = r.json()
            )
            return_results(results)
        else:
            return_error(f'Status Code: {r.status_code}\nResponse Body: {r.text}')


    def delete_profiles(self):
    '''
    Need to test
    '''
        url = f'{base_url}/profiles/{profileID}'

        r = requests.delete(url, headers=headers)

        if r.ok:
            results = CommandResults(
                outputs_prefix = 'Triage.profiles',
                outputs_key_field = 'data',
                # outputs = r.json()['data']
                outputs = r.json()
            )
            return_results(results)
        else:
            return_error(f'Status Code: {r.status_code}\nResponse Body: {r.text}')


def test():
    return 'ok'


def main():
    commands = {
        'test-module': test_module,
        'triage-query-samples': query_samples,
        'triage-submit-sample': submit_sample,
        'triage-get-sample': get_sample,
        'triage-get-sample-summary': get_sample_summary,
        'triage-delete-sample': delete_sample
        # Add in the rest of the commands, already coded, just add in and test
    }

    dmst_command = demisto.command()
    commands[dmst_command]()


if __name__ in ['__main__','__builtin__','builtins']:
    main()