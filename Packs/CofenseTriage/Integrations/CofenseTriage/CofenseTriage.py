from CommonServerPython import *

'''IMPORTS'''
import requests
from typing import Any, List, Dict

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS '''
BASE_URL = demisto.getParam('host').rstrip('/') + '/api/public/v1'  # type: str
TOKEN = demisto.getParam('token')  # type: str
USER = demisto.getParam('user')  # type: str
USE_SSL = not demisto.params().get('insecure', False)  # type: bool

HEADERS = {
    "Authorization": f"Token token={USER}:{TOKEN}",
    "Accept": "application/json"
}  # type: dict
DEFAULT_TIME_RANGE = '7 days'  # type: str
TIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'  # type: str

CATEGORIES = {
    1: 'Non-Malicious',
    2: 'Spam',
    3: 'Crimeware',
    4: 'Advanced Threats',
    5: 'Phishing Simulation'
}

# Severity levels are 4 - Critical, 3 - High, 2 - Medium, 1 - Low, 0 - Unknown
CATEGORIES_SEVERITY = {
    1: 1,  # non malicious -> low
    2: 0,  # spam -> unknown
    3: 2,  # crimeware -> medium
    4: 2,  # advanced threats -> medium
    5: 1  # phishing simulation -> low
}

TERSE_FIELDS = [
    'id',
    'cluster_id',
    'reporter_id',
    'location',
    'created_at',
    'reported_at',
    'report_subject',
    'report_body',
    'md5',
    'sha256',
    'category_id',
    'match_priority',
    'tags',
    'email_attachments'
]


# HELPER FUNCTIONS #
def snake_to_camel_keys(snake_list: List[Dict]) -> List[Dict]:
    def snake_to_camel(snake_str) -> str:
        if snake_str == 'id':
            return 'ID'
        components = snake_str.split('_')
        return ''.join(x.title() for x in components)

    return [{snake_to_camel(k): v for k, v in snake_d.items()} for snake_d in snake_list]


def split_snake(string: str) -> str:
    return string.replace("_", " ").title()


# MAIN FUNCTIONS #
def http_request(url_suffix: str, params=None, body=None, raw_response=False) -> Any:
    """
    Generic request to Cofense Triage. Client applications can make 25 requests to Cofense Triage
    within a five-minute interval using the Cofense Triage API.
    """
    response = requests.get(
        BASE_URL + url_suffix,
        headers=HEADERS,
        params=params,
        data=body,
        verify=USE_SSL,
    )
    try:
        if not response.ok:
            return_error(f'Call to Cofense Triage failed [{response.status_code}] - [{response.text}]')

        elif response.status_code == 206:  # 206 indicates Partial Content, reason will be in the warning header
            demisto.debug(str(response.headers))

        if raw_response:
            return response
        data = response.json() if response.text and response.text != '[]' else {}  # type: Any
        return data

    except TypeError as ex:
        demisto.debug(str(ex))
        return_error(f'Error in API call to Cofense Triage, could not parse result [{response.status_code}]')
        return {}


def get_fetch_response():
    start_date, _ = parse_date_range(demisto.getParam('date_range'), date_format=TIME_FORMAT)
    max_fetch = int(demisto.getParam('max_fetch'))  # type: int
    params = {
        'category_id': demisto.getParam('category_id'),
        'match_priority': demisto.getParam('match_priority'),
        'tags': demisto.getParam('tags'),
        'start_date': start_date,
    }

    # running the API command
    response = http_request(
        '/processed_reports',
        params=params,
    )

    return response, max_fetch


def test_function() -> None:
    try:
        response = requests.get(
            BASE_URL + '/processed_reports',
            headers=HEADERS,
            params="",
            verify=USE_SSL,
        )

        if response.ok:
            # test fetching mechanism
            if demisto.params().get('isFetch'):
                get_fetch_response()

            demisto.results('ok')

    except Exception as ex:
        demisto.debug(str(ex))
        return_error('API call to Cofense Triage failed, please check URL, or integration parameters.')


def fetch_reports() -> None:
    # parameters importing
    reports, max_fetch = get_fetch_response()

    # loading last_run
    last_run = json.loads(demisto.getLastRun().get('value', '{}'))
    already_fetched = last_run.get('already_fetched', [])

    # parsing outputs
    incidents = []
    for report in reports:
        if report.get('id') not in already_fetched:
            category_id, report_id = report.get('category_id'), report['id']
            report_body = report.pop('report_body')
            incident = {
                'name': f"cofense triage report {report_id}: {CATEGORIES.get(category_id, 'Unknown')}",
                'occurred': report.get('created_at'),
                'rawJSON': json.dumps(report),
                'severity': CATEGORIES_SEVERITY.get(category_id, 0)
            }

            # load HTML attachment into the incident
            attachment = load_attachment(report_body, report_id)
            if attachment:
                incident['attachment'] = attachment
            else:
                # attachment is not HTML file, keep it as plain text
                report['report_body'] = report_body
                incident['rawJSON'] = json.dumps(report)

            incidents.append(incident)
            already_fetched.append(report_id)
            if len(incidents) >= max_fetch:
                break

    demisto.incidents(incidents)
    last_run = {'already_fetched': already_fetched}
    demisto.setLastRun({'value': json.dumps(last_run)})


def load_attachment(report_body: Any, report_id: int) -> list:
    if report_body and 'HTML' in report_body:
        html_attachment = fileResult(filename=f'{report_id}-report.html', data=report_body.encode())
        attachment = {
            'path': html_attachment.get('FileID'),
            'name': html_attachment.get('FileName')
        }
        return [attachment]
    return []


def search_reports_command() -> None:
    # arguments importing
    subject = demisto.getArg('subject')  # type: str
    url = demisto.getArg('url')  # type: str
    file_hash = demisto.getArg('file_hash')  # type: str
    reported_at, _ = parse_date_range(demisto.args().get('reported_at', DEFAULT_TIME_RANGE))
    created_at, _ = parse_date_range(demisto.args().get('created_at', DEFAULT_TIME_RANGE))
    reporter = demisto.getArg('reporter')  # type: str
    max_matches = int(demisto.getArg('max_matches'))  # type: int
    verbose = demisto.getArg('verbose') == "true"

    # running the API command
    results = search_reports(subject, url, file_hash, reported_at, created_at, reporter, verbose, max_matches)

    # parsing outputs
    if results:
        ec = {'Cofense.Report(val.ID && val.ID == obj.ID)': snake_to_camel_keys(results)}
        hr = tableToMarkdown("Reports:", results, headerTransform=split_snake, removeNull=True)

        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['markdown'],
            'Contents': results if results else "no results were found",
            'HumanReadable': hr,
            'EntryContext': ec
        })
    else:
        return_outputs("no results were found.", {})


def search_reports(subject=None, url=None, file_hash=None, reported_at=None, created_at=None, reporter=None,
                   verbose=False, max_matches=30) -> list:
    params = {'start_date': datetime.strftime(reported_at, TIME_FORMAT)}
    reports = http_request(url_suffix='/processed_reports', params=params)

    if not isinstance(reports, list):
        reports = [reports]

    reporters = []  # type: list
    if reporter:
        reporters = get_all_reporters(time_frame=min(reported_at, created_at))

    matches = []

    for report in reports:
        if subject and subject != report.get('subject'):
            continue
        if url and url != report.get('url'):
            continue
        if created_at and 'created_at' in report and created_at >= datetime.strptime(report['created_at'], TIME_FORMAT):
            continue
        if file_hash and file_hash != report.get('md5') and file_hash != report.get('sha256'):
            continue
        if reporter and int(reporter) != report.get('reporter_id') and reporter not in reporters:
            continue

        if not verbose:
            # extract only relevant fields
            report = {key: report[key] for key in report.keys() & TERSE_FIELDS}

        matches.append(report)
        if len(matches) >= max_matches:
            break

    return matches


def get_all_reporters(time_frame) -> list:
    res = http_request('/reporters', params={'start_date': time_frame})
    if not isinstance(res, list):
        res = [res]
    reporters = [reporter.get('email') for reporter in res]

    return reporters


def get_reporter_command() -> None:
    # arguments importing
    reporter_id = demisto.getArg('reporter_id')  # type: str

    # running the API command
    res = get_reporter(reporter_id)

    # parsing outputs
    ec = {'Cofense.Reporter(val.ID && val.ID == obj.ID)': {'ID': reporter_id, 'Email': res}}
    hr = f'Reporter: {res}' if res else 'Could not find reporter with matching ID'
    return_outputs(readable_output=hr, outputs=ec)


def get_reporter(reporter_id) -> str:
    res = http_request(url_suffix=f'/reporters/{reporter_id}')
    if not isinstance(res, list):
        res = [res]
    reporter = res[0].get('email')

    return reporter


def get_attachment_command() -> None:
    # arguments importing
    attachment_id = demisto.getArg('attachment_id')  # type: str
    file_name = demisto.getArg('file_name') or attachment_id  # type: str

    # running the command
    res = get_attachment(attachment_id)

    # parsing outputs
    context_data = {'ID': attachment_id}
    demisto.results(fileResult(file_name, res.content))
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['markdown'],
        'Contents': '',
        'HumanReadable': '',
        'EntryContext': {'Cofense.Attachment(val.ID == obj.ID)': context_data}
    })


def get_attachment(attachment_id):
    response = http_request(f'/attachment/{attachment_id}', params={'attachment_id': attachment_id}, raw_response=True)
    if not response.ok:
        return_error(f'Call to Cofense Triage failed [{response.status_code}]')
    else:
        return response


def get_report_by_id_command() -> None:
    # arguments importing
    report_id = int(demisto.getArg('report_id'))  # type: int
    verbose = demisto.getArg('verbose') == "true"

    # running the command
    res = get_report_by_id(report_id)[0]

    # parsing outputs
    if not verbose:
        # extract only relevant fields
        res = {k: res[k] for k in res.keys() & TERSE_FIELDS}

    # get the report body, and create html file if necessary
    if res:
        parse_report_body(res)
        res['reporter'] = get_reporter(res.get('reporter_id'))  # enrich: id -> email
        hr = tableToMarkdown("Report Summary:", res, headerTransform=split_snake, removeNull=True)
        ec = {'Cofense.Report(val.ID && val.ID == obj.ID)': snake_to_camel_keys([res])}
        return_outputs(readable_output=hr, outputs=ec)

    else:
        return_error('Could not find report with matching ID')


def parse_report_body(report) -> None:
    if 'report_body' in report and 'HTML' in report['report_body']:
        attachment = fileResult(
            filename=f'{report.get("id")}-report.html',
            data=report.get('report_body').encode(),
        )
        attachment['HumanReadable'] = '### Cofense HTML Report:\nHTML report download request has been completed'
        demisto.results(attachment)
        del report['report_body']


def get_report_by_id(report_id):
    response = http_request(url_suffix=f'/reports/{report_id}', params={'report_id': report_id})
    return response


try:
    handle_proxy()

    # COMMANDS
    if demisto.command() == 'test-module':
        test_function()

    if demisto.command() == 'fetch-incidents':
        fetch_reports()

    elif demisto.command() == 'cofense-search-reports':
        search_reports_command()

    elif demisto.command() == 'cofense-get-attachment':
        get_attachment_command()

    elif demisto.command() == 'cofense-get-reporter':
        get_reporter_command()

    elif demisto.command() == 'cofense-get-report-by-id':
        get_report_by_id_command()

except Exception as e:
    return_error(str(e))
    raise
