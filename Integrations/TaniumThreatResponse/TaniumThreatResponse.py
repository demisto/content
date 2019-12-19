
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
import json
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

''' GLOBALS/PARAMS '''
FETCH_TIME = demisto.params().get('fetch_time')
DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'


class Client(BaseClient):
    def __init__(self, base_url, username, password, domain, **kwargs):
        self.username = username
        self.password = password
        self.domain = domain
        self.session = ''
        super(Client, self).__init__(base_url, **kwargs)

    def do_request(self, method, url_suffix, data=None):
        if not self.session:
            self.update_session()

        res = self._http_request(method, url_suffix, headers={'session': self.session}, json_data=data,
                                 resp_type='response', ok_codes=[200, 400, 403, 404])

        if res.status_code == 403:
            self.update_session()
            res = self._http_request(method, url_suffix, headers={'session': self.session}, json_data=data,
                                     ok_codes=[200, 400, 404])
            return res

        if res.status_code == 404 or res.status_code == 400:
            raise requests.HTTPError(res.json().get('text'))

        return res.json()

    def update_session(self):
        body = {
            'username': self.username,
            'domain': self.domain,
            'password': self.password
        }

        res = self._http_request('GET', '/api/v2/session/login', json_data=body, ok_codes=[200])

        self.session = res.get('data').get('session')
        return self.session

    def login(self):
        return self.update_session()

    def alarm_to_incident(self, alarm):
        intel_doc_id = alarm.get('intelDocId', '')
        host = alarm.get('computerName', '')
        details = alarm.get('details')

        if details:
            details = json.loads(alarm['details'])
            alarm['details'] = details

        intel_doc = ''
        if intel_doc_id:
            raw_response = self.do_request('GET', f'/plugin/products/detect3/api/v1/intels/{intel_doc_id}')
            intel_doc = raw_response.get('name')

        return {
            'name': f'{host} found {intel_doc}',
            'occurred': alarm.get('alertedAt'),
            'rawJSON': json.dumps(alarm)
        }

    def get_intel_doc_item(self, intel_doc):
        return {
            'ID': intel_doc.get('id'),
            'Name': intel_doc.get('name'),
            'AlertCount': intel_doc.get('alertCount'),
            'UnresolvedAlertCount': intel_doc.get('unresolvedAlertCount'),
            'CreatedAt': intel_doc.get('createdAt'),
            'UpdatedAt': intel_doc.get('updatedAt')
        }


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module(client, data_args):
    if client.login():
        return demisto.results('ok')
    raise ValueError('Test Tanium integration failed - please check your username and password')


def get_intel_doc(client, data_args):
    id_ = data_args.get('intel-doc-id')
    raw_response = client.do_request('GET', f'/plugin/products/detect3/api/v1/intels/{id_}')
    intel_doc = client.get_intel_doc_item(raw_response)

    context = createContext(intel_doc, removeNull=True)
    outputs = {'Tanium.IntelDoc(val.ID && val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Intel Doc information', intel_doc)
    return human_readable, outputs, raw_response


def get_intel_docs(client, data_args):
    count = int(data_args.get('limit'))
    raw_response = client.do_request('GET', '/plugin/products/detect3/api/v1/intels/')

    intel_docs = []
    # ignoring the last item because its not a saved action object
    for item in raw_response[:count]:
        intel_doc = client.get_intel_doc_item(item)
        intel_docs.append(intel_doc)

    context = createContext(intel_docs, removeNull=True)
    outputs = {'Tanium.IntelDoc(val.ID && val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Intel docs', intel_docs)
    return human_readable, outputs, raw_response

def fetch_incidents(client):
    """
    Fetch events from this integration and return them as Demisto incidents

    returns:
        Demisto incidents
    """
    # demisto.getLastRun() will returns an obj with the previous run in it.
    last_run = demisto.getLastRun()
    # Get the last fetch time and data if it exists
    last_fetch = last_run.get('time')

    # Handle first time fetch, fetch incidents retroactively
    if not last_fetch:
        last_fetch, _ = parse_date_range(FETCH_TIME, date_format=DATE_FORMAT)

    last_fetch = datetime.strptime(last_fetch, DATE_FORMAT)
    current_fetch = last_fetch
    raw_response = client.do_request('GET', '/plugin/products/detect3/api/v1/alerts')

    # convert the data/events to demisto incidents
    incidents = []
    for alarm in raw_response:
        incident = client.alarm_to_incident(alarm)
        temp_date = datetime.strptime(incident.get('occurred'), DATE_FORMAT)

        # update last run
        if temp_date > last_fetch:
            last_fetch = temp_date + timedelta(seconds=1)

        # avoid duplication due to weak time query
        if temp_date > current_fetch:
            incidents.append(incident)

    demisto.setLastRun({'time':  datetime.strftime(last_fetch, DATE_FORMAT)})

    return demisto.incidents(incidents)


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    params = demisto.params()
    username = params.get('credentials').get('identifier')
    password = params.get('credentials').get('password')
    domain = params.get('domain')
    # Remove trailing slash to prevent wrong URL path to service
    server = params['url'].strip('/')
    # Should we use SSL
    use_ssl = not params.get('insecure', False)

    # Remove proxy if not set to true in params
    handle_proxy()
    command = demisto.command()
    client = Client(server, username, password, domain, verify=use_ssl)
    demisto.info(f'Command being called is {command}')

    commands = {
        f'test-module': test_module,
        f'tn-get-intel-doc-by-id': get_intel_doc,
        f'tn-list-intel-docs': get_intel_docs
    }

    try:
        if command == 'fetch-incidents':
            return fetch_incidents(client)

        if command in commands:
            human_readable, outputs, raw_response = commands[command](client, demisto.args())
            return_outputs(readable_output=human_readable, outputs=outputs, raw_response=raw_response)
        # Log exceptions
    except Exception as e:
        err_msg = f'Error in Tanium v2 Integration [{e}]'
        return_error(err_msg, error=e)


if __name__ == 'builtins':
    main()
