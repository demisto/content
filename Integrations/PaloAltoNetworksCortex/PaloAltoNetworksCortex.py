import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''
import os
import requests
import json
from pancloud import LoggingService, Credentials
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBAL VARS '''
AUTH_ID = demisto.params().get('auth_id')
# If there's a stored token in integration context, it's newer than current
TOKEN = demisto.getIntegrationContext().get('token')
if not TOKEN:
    TOKEN = demisto.params().get('token')

ENC_KEY = demisto.params().get('auth_key')

USE_SSL = not demisto.params().get('insecure', False)
TOKEN_RETRIEVAL_URL = 'https://demistobot.demisto.com/panw-token'
FETCH_QUERY = None

FIRST_FETCH_TIMESTAMP = demisto.params().get('first_fetch_timestamp', '').strip()
if not FIRST_FETCH_TIMESTAMP:
    FIRST_FETCH_TIMESTAMP = '24 hours'

if not demisto.params().get('proxy', False):
    os.environ.pop('HTTP_PROXY', '')
    os.environ.pop('HTTPS_PROXY', '')
    os.environ.pop('http_proxy', '')
    os.environ.pop('https_proxy', '')

FETCH_QUERY_DICT = {
    'Traps Threats': 'SELECT * FROM tms.threat',
    'Firewall Threats': 'SELECT * FROM panw.threat',
    'Cortex XDR Analytics': 'SELECT * FROM magnifier.alert'
}

THREAT_TABLE_HEADERS = [
    'id', 'score', 'risk-of-app', 'type', 'action', 'app', 'pcap_id', 'proto', 'dst', 'reportid',
    'rule', 'category-of-threatid', 'characteristic-of-app', 'device_name', 'subtype',
    'time_received', 'pcap', 'name-of-threatid', 'severity', 'nat', 'natdport', 'natdst',
    'natsrc', 'src', 'category-of-app', 'srcloc', 'dstloc', 'category', 'SHA256', 'filetype', 'filename'
]

TRAFFIC_TABLE_HEADERS = [
    'id', 'score', 'aggregations.size', 'action', 'app', 'proto', 'dst', 'rule', 'characteristic-of-app',
    'device_name', 'risk-of-app', 'natsport', 'start', 'subcategory-of-app', 'time_received',
    'nat', 'natdport', 'natdst', 'natsrc', 'src', 'category-of-app', 'srcloc', 'dstloc'
]

COMMON_HEADERS = [
    'id', 'score', 'action', 'app', 'proto', 'dst', 'rule', 'characteristic-of-app', 'device_name',
    'nat', 'natdport', 'natdst', 'natsrc', 'src', 'category-of-app', 'srcloc', 'dstloc', 'filetype',
    'SHA256', 'filename'
]

''' HELPER FUNCTIONS '''


def get_encrypted(auth_id: str, key: str) -> str:
    """

    Args:
        auth_id (str): auth_id from Demistobot
        key (str): key from Demistobot

    Returns:

    """
    def create_nonce() -> bytes:
        return os.urandom(12)

    def encrypt(string: str, enc_key: str) -> bytes:
        """

        Args:
            enc_key (str):
            string (str):

        Returns:
            bytes:
        """
        # String to bytes
        enc_key = enc_key.encode()
        # Create key
        aes_gcm = AESGCM(enc_key)
        # Create nonce
        nonce = create_nonce()
        # Create ciphered data
        data = string.encode()
        ct = aes_gcm.encrypt(nonce, data, None)
        return base64.b64encode(nonce + ct)
    now = epoch_seconds()
    return encrypt(f'{now}:{auth_id}', key).decode('utf-8')


def prepare_fetch_query(fetch_timestamp):
    query = FETCH_QUERY_DICT[demisto.params().get('fetch_query', 'Traps Threats')]
    if 'tms' in query:
        query += f" WHERE serverTime>'{fetch_timestamp}'"
        FETCH_SEVERITY = demisto.params().get('traps_severity')
        if not FETCH_SEVERITY:
            FETCH_SEVERITY = ['all']
        if 'all' not in FETCH_SEVERITY:
            query += ' AND ('
            for index, severity in enumerate(FETCH_SEVERITY):
                if index == (len(FETCH_SEVERITY) - 1):
                    query += f"messageData.trapsSeverity='{severity}'"
                else:
                    query += f"messageData.trapsSeverity='{severity}' OR "
            query += ')'
    if 'panw' in query:
        query += f' WHERE receive_time>{fetch_timestamp}'
        FETCH_SEVERITY = demisto.params().get('firewall_severity')
        if not FETCH_SEVERITY:
            FETCH_SEVERITY = ['all']
        FETCH_SUBTYPE = demisto.params().get('firewall_subtype')
        if not FETCH_SUBTYPE:
            FETCH_SUBTYPE = ['all']
        if 'all' not in FETCH_SUBTYPE:
            query += ' AND ('
            for index, subtype in enumerate(FETCH_SUBTYPE):
                if index == (len(FETCH_SUBTYPE) - 1):
                    query += f"subtype='{subtype}'"
                else:
                    query += f"subtype='{subtype}' OR "
            query += ')'
        if 'all' not in FETCH_SEVERITY:
            query += ' AND ('
            for index, severity in enumerate(FETCH_SEVERITY):
                if index == (len(FETCH_SEVERITY) - 1):
                    query += f"severity='{severity}'"
                else:
                    query += f"severity='{severity}' OR "
            query += ')'
    if 'magnifier' in query:
        query += f' WHERE time_generated>{fetch_timestamp}'
        FETCH_SEVERITY = demisto.params().get('xdr_severity')
        if not FETCH_SEVERITY:
            FETCH_SEVERITY = ['all']
        FETCH_CATEGORY = demisto.params().get('xdr_category')
        if not FETCH_CATEGORY:
            FETCH_CATEGORY = ['all']
        if 'all' not in FETCH_CATEGORY:
            query += ' AND ('
            for index, subtype in enumerate(FETCH_CATEGORY):
                if index == (len(FETCH_CATEGORY) - 1):
                    query += f"alert.category.keyword='{subtype}'"
                else:
                    query += f"alert.category.keyword='{subtype}' OR "
            query += ')'
        if 'all' not in FETCH_SEVERITY:
            query += ' AND ('
            for index, severity in enumerate(FETCH_SEVERITY):
                if index == (len(FETCH_SEVERITY) - 1):
                    query += f"alert.severity.keyword='{severity}'"
                else:
                    query += f"alert.severity.keyword='{severity}' OR "
            query += ')'
        # Only get new Alerts
        query += ' AND sub_type.keyword = \'New\''
    return query


def epoch_seconds(d=None):
    """
    Return the number of seconds for given date. If no date, return current.

    parameter: (date) d
        The date to convert to seconds

    returns:
        The date in seconds
    """
    if not d:
        d = datetime.utcnow()
    return int((d - datetime.utcfromtimestamp(0)).total_seconds())


def get_access_token():
    integration_context = demisto.getIntegrationContext()
    access_token = integration_context.get('access_token')
    stored = integration_context.get('stored')
    if access_token and stored:
        if epoch_seconds() - stored < 60 * 60 - 30:
            return access_token
    headers = {
        'Authorization': AUTH_ID,
        'Accept': 'application/json'
    }

    dbot_response = requests.get(
        TOKEN_RETRIEVAL_URL,
        headers=headers,
        params={'token': get_encrypted(TOKEN, ENC_KEY)},
        verify=USE_SSL
    )
    if dbot_response.status_code not in {200, 201}:
        msg = 'Error in authentication. Try checking the credentials you entered.'
        try:
            demisto.info('Authentication failure from server: {} {} {}'.format(
                dbot_response.status_code, dbot_response.reason, dbot_response.text))
            err_response = dbot_response.json()
            server_msg = err_response.get('message')
            if not server_msg:
                title = err_response.get('title')
                detail = err_response.get('detail')
                if title:
                    server_msg = f'{title}. {detail}'
            if server_msg:
                msg += ' Server message: {}'.format(server_msg)
        except Exception as ex:
            demisto.error('Failed parsing error response: [{}]. Exception: {}'.format(err_response.content, ex))
        raise Exception(msg)
    try:
        parsed_response = dbot_response.json()
    except ValueError:
        raise Exception(
            'There was a problem in retrieving an updated access token.\n'
            'The response from the Demistobot server did not contain the expected content.'
        )
    access_token = parsed_response.get('access_token')
    api_url = parsed_response.get('url')
    token = parsed_response.get('token')

    demisto.setIntegrationContext({
        'access_token': access_token,
        'stored': epoch_seconds(),
        'api_url': api_url,
        'token': token
    })
    return access_token


def initial_logging_service():
    api_url = demisto.getIntegrationContext().get('api_url', 'https://api.us.paloaltonetworks.com')
    credentials = Credentials(
        access_token=get_access_token(),
        verify=USE_SSL
    )
    logging_service = LoggingService(
        url=api_url,
        credentials=credentials
    )

    return logging_service


def poll_query_result(query_id):

    logging_service = initial_logging_service()

    poll_params = {  # Prepare 'poll' params
        "maxWaitTime": 30000  # waiting for response up to 3000ms
    }

    # we poll the logging service until we have a complete response
    response = logging_service.poll(query_id, 0, poll_params)

    return response


def query_loggings(query_data):
    """
    This function handles all the querying of Cortex Logging service
    """

    logging_service = initial_logging_service()

    response = logging_service.query(query_data)
    query_result = response.json()

    if not response.ok:
        status_code = query_result.get('statusCode', '')
        error = query_result.get('error', '')
        message = query_result.get('payload', {}).get('message', '')
        raise Exception(f"Error in query to Cortex [{status_code}] - {error}: {message}")

    try:
        query_id = query_result['queryId']  # access 'queryId' from 'query' response
    except Exception as e:
        raise Exception('Received error %s when querying logs.' % e)

    poll_response = poll_query_result(query_id)
    return poll_response


def transform_row_keys(row):
    transformed_row = {}
    for metric, value in row.items():
        if metric == 'filedigest':
            transformed_row['SHA256'] = value
        elif metric == 'misc':
            transformed_row['filename'] = value
        elif metric == 'category' and str(value) == '1':
            transformed_row['category'] = 'malicious'
        else:
            transformed_row[metric] = value
    return transformed_row


def results_screener(table_name, full_results):
    """
    This function is used to make sure we include only pre-defined metrics in the human readable
    """
    screened_results = []

    if table_name == "traffic":
        for row in full_results:
            screened_row = {metric: value for metric, value in row.items() if metric in TRAFFIC_TABLE_HEADERS}
            screened_results.append(screened_row)
    elif table_name == "threat":
        for row in full_results:
            screened_row = {metric: value for metric, value in row.items() if metric in THREAT_TABLE_HEADERS}
            screened_results.append(screened_row)
    elif table_name == "common":
        for row in full_results:
            screened_row = {metric: value for metric, value in row.items() if metric in COMMON_HEADERS}
            screened_results.append(screened_row)
    else:
        return full_results

    return screened_results


def get_start_time(date_type, time_value):
    current_date = datetime.now()
    if date_type == 'minutes':
        return current_date - timedelta(minutes=time_value)
    elif date_type == 'days':
        return current_date - timedelta(days=time_value)
    elif date_type == 'weeks':
        return current_date - timedelta(weeks=time_value)


def convert_log_to_incident(log):
    log_contents = log.get('_source')
    if log_contents.get('id'):
        log_contents['xdr_id'] = log_contents.get('id')  # XDR ID before it is overwritten
    log_contents['id'] = log.get('_id')
    log_contents['score'] = log.get('_score')
    if 'Traps' in FETCH_QUERY:  # type: ignore
        occurred = log_contents.get('generatedTime')
        time_received = log_contents.get('serverTime')
    elif 'Firewall' in FETCH_QUERY:  # type: ignore
        time_generated = log_contents.get('time_generated')
        occurred = datetime.utcfromtimestamp(time_generated).isoformat() + 'Z'
        time_received = log_contents.get('receive_time')
    elif 'XDR' in FETCH_QUERY:  # type: ignore
        # first_detected_at in alert.schedule can be present or not, can be in s or ms
        # if not detected, fallback to time_generated
        try:
            time_received = int(log_contents.get('time_generated')) or 0
        except ValueError:
            time_received = 0

        occurred_raw = 0
        first_detected_at = None
        try:
            first_detected_at = str(log_contents.get('alert', {}).get('schedule', {}).get('first_detected_at'))
        except AttributeError:
            first_detected_at = None
        if first_detected_at is not None:
            if len(first_detected_at) == 13:  # ms
                occurred_raw = int(float(first_detected_at) / 1000)
            elif len(first_detected_at) == 10:  # s
                occurred_raw = int(first_detected_at)
            else:  # unknown length, fallback to time_received
                occurred_raw = int(time_received)
        else:  # not present, fallback to time_received
            occurred_raw = int(time_received)
        occurred = datetime.utcfromtimestamp(occurred_raw).isoformat() + 'Z'

    # stringifying dictionary values for fetching. (json.dumps() doesn't stringify dictionary values)
    event_id = log.get('_id', '')
    incident = {
        'name': 'Cortex Event ' + event_id,
        'rawJSON': json.dumps(log_contents, ensure_ascii=False),
        'occurred': occurred
    }
    return incident, time_received


''' COMMANDS FUNCTIONS '''


def query_logs_command():
    """
    Return the result of querying the Logging service
    """
    args = demisto.args()
    start_time = args.get('startTime')
    end_time = args.get('endTime')
    time_range = args.get('timeRange')
    time_value = args.get('rangeValue')

    if time_range:
        if time_value:
            service_end_date = datetime.now()
            service_start_date = get_start_time(time_range, int(time_value))
        else:
            raise Exception('Enter timeRange and timeValue, or startTime and endTime')
    else:
        time_format = '%Y-%m-%d %H:%M:%S'
        # Thu Jan 01 02:00:00 IST 1970' does not match format '%Y-%m-%d %H:%M:%S'
        service_start_date = datetime.strptime(start_time, time_format)
        service_end_date = datetime.strptime(end_time, time_format)

    # transforms datetime object to epoch time
    service_start_date_epoch = int(service_start_date.strftime('%s'))
    service_end_date_epoch = int(service_end_date.strftime('%s'))

    query = args.get('query')

    if 'limit' not in query.lower():
        query += ' LIMIT 100'

    query_data = {
        "query": query,
        "startTime": service_start_date_epoch,
        "endTime": service_end_date_epoch,
    }

    response = query_loggings(query_data)

    try:
        response_json = response.json()
        query_status = response_json.get('queryStatus', '')
        if query_status in {'RUNNING', 'JOB_FAILED'}:
            raise Exception(f'Logging query job failed with status: {query_status}')
        result = response_json.get('result', {})
        pages = result.get('esResult', {}).get('hits', {}).get('hits', [])
        table_name = result['esQuery']['table'][0].split('.')[1]
    except ValueError:
        raise Exception('Failed to parse the response from Cortex')

    output = []

    for page in pages:
        row_contents = page.get('_source')
        row_contents['id'] = page.get('_id')
        row_contents['score'] = page.get('_score')
        transformed_row = transform_row_keys(row_contents)
        output.append(transformed_row)

    screened_results = results_screener('common', output)

    entry = {
        'Type': entryTypes['note'],
        'Contents': output,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Logs ' + table_name + ' table', screened_results),
        'EntryContext': {
            'Cortex.Logging(val.id===obj.id)': output
        }
    }

    return entry


def get_critical_logs_command():
    """
    Queries Cortex Logging according to a pre-set query
    """

    args = demisto.args()

    start_time = args.get('startTime')
    end_time = args.get('endTime')
    value = args.get('logsAmount')
    time_range = args.get('timeRange')
    time_value = args.get('rangeValue')

    if time_range:
        if time_value:
            service_end_date = datetime.now()
            service_start_date = get_start_time(time_range, int(time_value))
        else:
            raise Exception('Enter timeRange and timeValue, or startTime and endTime')
    else:
        # parses user input to datetime object
        service_start_date = datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S")
        service_end_date = datetime.strptime(end_time, "%Y-%m-%d %H:%M:%S")

    # transforms datetime object to epoch time
    service_start_date_epoch = int(service_start_date.strftime("%s"))
    service_end_date_epoch = int(service_end_date.strftime("%s"))

    api_query = "SELECT * FROM panw.threat WHERE severity = '5' LIMIT " + value

    query_data = {
        "query": api_query,
        "startTime": service_start_date_epoch,
        "endTime": service_end_date_epoch,
    }

    response = query_loggings(query_data)

    try:
        result = response.json()['result']
        pages = result.get('esResult', {}).get('hits', {}).get('hits', [])
        table_name = result['esQuery']['table'][0].split('.')[1]
    except ValueError:
        raise Exception('Failed to parse the response from Cortex')

    output = []

    for page in pages:
        row_contents = page.get('_source')
        row_contents['id'] = page.get('_id')
        row_contents['score'] = page.get('_score')
        transformed_row = transform_row_keys(row_contents)
        output.append(transformed_row)

    screened_results = results_screener('threat', output)

    entry = {
        'Type': entryTypes['note'],
        'Contents': output,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Logs ' + table_name + ' table', screened_results),
        'EntryContext': {
            'Cortex.Logging(val.id==obj.id)': output
        }
    }
    return entry


def get_social_applications_command():
    """ Queries Cortex Logging according to a pre-set query """

    args = demisto.args()

    start_time = args.get('startTime')
    end_time = args.get('endTime')
    value = args.get('logsAmount')
    time_range = args.get('timeRange')
    time_value = args.get('rangeValue')

    if time_range:
        if time_value:
            service_end_date = datetime.now()
            service_start_date = get_start_time(time_range, int(time_value))
        else:
            raise Exception('Enter timeRange and timeValue, or startTime and endTime')
    else:
        # parses user input to datetime object
        service_start_date = datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S")
        service_end_date = datetime.strptime(end_time, "%Y-%m-%d %H:%M:%S")

    # transforms datetime object to epoch time
    service_start_date_epoch = int(service_start_date.strftime("%s"))
    service_end_date_epoch = int(service_end_date.strftime("%s"))

    api_query = "SELECT * FROM panw.traffic WHERE subcategory-of-app = 'social-networking' LIMIT " + value

    query_data = {
        "query": api_query,
        "startTime": service_start_date_epoch,
        "endTime": service_end_date_epoch,
    }

    response = query_loggings(query_data)

    try:
        result = response.json()['result']
        pages = result.get('esResult', {}).get('hits', {}).get('hits', [])
        table_name = result['esQuery']['table'][0].split('.')[1]
    except ValueError:
        raise Exception('Failed to parse the response from Cortex')

    output = []

    for page in pages:
        row_contents = page.get('_source')
        row_contents['id'] = page.get('_id')
        row_contents['score'] = page.get('_score')
        transformed_row = transform_row_keys(row_contents)
        output.append(transformed_row)

    screened_results = results_screener('traffic', output)

    entry = {
        'Type': entryTypes['note'],
        'Contents': output,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Logs ' + table_name + ' table', screened_results),
        'EntryContext': {
            'Cortex.Logging(val.id===obj.id)': output
        }
    }
    return entry


def search_by_file_hash_command():
    """
    Queries Cortex Logging according to a pre-set query
    """

    args = demisto.args()

    start_time = args.get('startTime')
    end_time = args.get('endTime')
    value = args.get('logsAmount')
    time_range = args.get('timeRange')
    time_value = args.get('rangeValue')
    filehash = args.get('SHA256')

    if (time_range):
        if (time_value):
            service_end_date = datetime.now()
            service_start_date = get_start_time(time_range, int(time_value))
        else:
            raise Exception('Please enter timeRange and timeValue, or startTime and endTime')
    else:
        # parses user input to datetime object
        service_start_date = datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S")
        service_end_date = datetime.strptime(end_time, "%Y-%m-%d %H:%M:%S")

    # transforms datetime object to epoch time
    service_start_date_epoch = int(service_start_date.strftime("%s"))
    service_end_date_epoch = int(service_end_date.strftime("%s"))

    api_query = "SELECT * FROM panw.threat WHERE filedigest='" + filehash + "' LIMIT " + value

    query_data = {
        "query": api_query,
        "startTime": service_start_date_epoch,
        "endTime": service_end_date_epoch,
    }

    response = query_loggings(query_data)

    try:
        result = response.json()['result']
        pages = result.get('esResult', {}).get('hits', {}).get('hits', [])
        table_name = result['esQuery']['table'][0].split('.')[1]
    except ValueError:
        raise Exception('Failed to parse the response from Cortex')

    output = []

    for page in pages:
        row_contents = page.get('_source')
        row_contents['id'] = page.get('_id')
        row_contents['score'] = page.get('_score')
        transformed_row = transform_row_keys(row_contents)
        output.append(transformed_row)

    screened_results = results_screener('threat', output)

    entry = {
        'Type': entryTypes['note'],
        'Contents': output,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Logs ' + table_name + ' table', screened_results),
        'EntryContext': {
            'Cortex.Logging(val.id==obj.id)': output
        }
    }
    return entry


def process_incident_pairs(incident_pairs, max_incidents):
    sorted_pairs = sorted(incident_pairs, key=lambda x: x[1])
    sorted_pairs = sorted_pairs[:max_incidents]
    max_timestamp = sorted_pairs[-1][1]
    return list(map(lambda x: x[0], sorted_pairs)), max_timestamp


def fetch_incidents():

    last_run = demisto.getLastRun()
    last_fetched_event_timestamp = last_run.get('last_fetched_event_timestamp')
    last_query_id = last_run.get('last_query_id')

    if last_query_id:
        # Need to poll query results fron last run
        response = poll_query_result(last_query_id)
    else:
        if last_fetched_event_timestamp is not None:
            last_fetched_event_timestamp = datetime.strptime(last_fetched_event_timestamp, '%Y-%m-%dT%H:%M:%S.%f')
        else:
            last_fetched_event_timestamp, _ = parse_date_range(FIRST_FETCH_TIMESTAMP)

        # Need sometime in the future, so the timestamp will be taken from the query
        service_end_date_epoch = int(datetime.now().strftime('%s')) + 1000

        if 'Firewall' in FETCH_QUERY or 'XDR' in FETCH_QUERY:  # type: ignore
            fetch_timestamp = int(last_fetched_event_timestamp.strftime('%s'))
        elif 'Traps' in FETCH_QUERY:  # type: ignore
            fetch_timestamp = last_fetched_event_timestamp.strftime('%Y-%m-%dT%H:%M:%S.%fZ')

        query = prepare_fetch_query(fetch_timestamp)

        query_data = {
            'query': query,
            'startTime': 0,
            'endTime': service_end_date_epoch,
        }

        response = query_loggings(query_data)

    try:
        response_json = response.json()
        query_status = response_json.get('queryStatus', '')
        if query_status == 'JOB_FAILED':
            raise Exception(f'Logging query job failed with status: JOB_FAILED\nResponse: {response.text}')
        elif query_status == 'RUNNING':
            if isinstance(last_fetched_event_timestamp, datetime):
                # In case we don't have query ID from previous run
                last_fetched_event_timestamp = last_fetched_event_timestamp.strftime('%Y-%m-%dT%H:%M:%S.%f')
            # If query job is still running after 30 seconds (max timeout), pass it to next run
            demisto.setLastRun({
                'last_fetched_event_timestamp': last_fetched_event_timestamp,
                'last_query_id': response_json.get('queryId', '')
            })
            demisto.incidents([])
            return
        result = response_json.get('result', {})
        pages = result.get('esResult', {}).get('hits', {}).get('hits', [])
    except ValueError:
        raise Exception('Failed to parse the response from Cortex')

    incident_pairs = []

    max_fetched_event_timestamp = last_fetched_event_timestamp
    for page in pages:
        incident, time_received = convert_log_to_incident(page)
        if 'Firewall' in FETCH_QUERY or 'XDR' in FETCH_QUERY:  # type: ignore
            time_received_dt = datetime.fromtimestamp(time_received)
        elif 'Traps' in FETCH_QUERY:  # type: ignore
            time_received_dt = datetime.strptime(time_received, '%Y-%m-%dT%H:%M:%S.%fZ')
        incident_pairs.append((incident, time_received_dt))
    if incident_pairs:
        incidents, max_fetched_event_timestamp = process_incident_pairs(incident_pairs, 100)  # max 100 per run
        demisto.setLastRun({
            'last_fetched_event_timestamp': max_fetched_event_timestamp.strftime('%Y-%m-%dT%H:%M:%S.%f')
        })
        demisto.incidents(incidents)
    else:
        demisto.incidents([])


''' EXECUTION CODE '''


def main():
    global FETCH_QUERY
    FETCH_QUERY = demisto.params().get('fetch_query', 'Traps Threats')

    LOG('command is %s' % (demisto.command(),))
    try:
        if demisto.command() == 'test-module':
            if demisto.params().get('isFetch'):
                last_fetched_event_timestamp, _ = parse_date_range(FIRST_FETCH_TIMESTAMP)
            test_args = {
                "query": "SELECT * FROM panw.threat LIMIT 1",
                "startTime": 0,
                "endTime": 1609459200,
            }
            if query_loggings(test_args):
                demisto.results('ok')
            else:
                demisto.results('test failed')
        elif demisto.command() == 'cortex-query-logs':
            demisto.results(query_logs_command())
        elif demisto.command() == 'cortex-get-critical-threat-logs':
            demisto.results(get_critical_logs_command())
        elif demisto.command() == 'cortex-get-social-applications':
            demisto.results(get_social_applications_command())
        elif demisto.command() == 'cortex-search-by-file-hash':
            demisto.results(search_by_file_hash_command())
        elif demisto.command() == 'fetch-incidents':
            fetch_incidents()
    except Exception as e:
        error_message = str(e)
        if demisto.command() == 'fetch-incidents':
            LOG(error_message)
            LOG.print_log()
            raise
        else:
            return_error(error_message)


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
