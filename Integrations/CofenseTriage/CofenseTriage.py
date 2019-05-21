import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

'''IMPORTS'''
import requests
from typing import Any, List, Dict

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS '''
BASE_URL = demisto.getParam('host').rstrip('/') + '/api/public/v1/'  # type: str
TOKEN = demisto.getParam('token')  # type: str
USER = demisto.getParam('user')  # type: str
HEADERS = {
    "Authorization": f"Token token={USER}:{TOKEN}",
    "Accept": "application/json"
}  # type: dict
USE_SSL = not demisto.params().get('insecure', False)  # type: bool
DEFAULT_TIME_RANGE = '3 days'
TIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'

CATEGORIES = {
    1: 'Non-Malicious',
    2: 'Spam',
    3: 'Crimeware',
    4: 'Advanced Threats',
    5: 'Phishing Simulation'
}

# Severity levels are 4 - Critical, 3 - High, 2 - Medium, 1 - Low, 0 - Unknown
CATEGORIES_SEVERITY = {
    1: 1,
    2: 1,
    3: 3,
    4: 4,
    5: 1
}


def snake_to_camel_keys(snake_list: List[Dict]) -> List[Dict]:
    def snake_to_camel(snake_str):
        components = snake_str.split('_')
        return ''.join(x.title() for x in components)

    # if not isinstance(snake_list, list):
    #     snake_list = [snake_list]
    return [{snake_to_camel(k): v for k, v in snake_d.items()} for snake_d in snake_list]


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
        if raw_response:
            return response

        data = response.json() if response.text and response.text != '[]' else {}  # type: Any
        if not response.ok:
            return_error(f'Call to Cofense Triage failed [{response.status_code}]')

        elif response.status_code == 206:  # 206 indicates Partial Content, reason will be in the warning header
            demisto.debug(str(response.headers))

        return data

    except TypeError as ex:
        demisto.debug(str(ex))
        return_error(f'Error in API call to Cofense Triage, could not parse result [{response.status_code}]')
        return {}


def test_function() -> None:
    try:
        response = requests.get(
            BASE_URL + 'processed_reports',
            headers=HEADERS,
            params="",
            verify=USE_SSL,
        )
        if response.ok:
            demisto.results('ok')

        else:
            return_error(f'API call to Cofense Triage failed. Please check authentication related parameters.'
                         f' [{response.status_code}] - {response.reason}')

    except Exception as ex:
        demisto.debug(str(ex))
        return_error(f'API call to Cofense Triage failed, Please check authentication related parameters.')


def fetch_reports() -> None:
    start_date, end_date = parse_date_range(demisto.getParam('date_range'), date_format=TIME_FORMAT)
    params = {
        'category_id': demisto.getParam('category_id'),
        # 'fields[]': argToList(demisto.getParam('fields')),  # fetch all of them
        'match_priority': demisto.getParam('match_priority'),
        'tags': demisto.getParam('tags'),
        'start_date': start_date,
        'end_date': end_date
    }
    reports = http_request(url_suffix='processed_reports', params=params)
    last_run = json.loads(demisto.getLastRun().get('value', '{}'))
    already_fetched = last_run.get('already_fetched', [])

    incidents = []
    for report in reports:
        if report.get('id') not in already_fetched:
            category_id = report.get('category_id')
            incident = {
                'name': f"cofense triage report {report['id']}: {CATEGORIES.get(category_id, 'Unknown')}",
                'occurred': report.get('created_at'),
                'rawJSON': json.dumps(report),
                'severity': CATEGORIES_SEVERITY.get(category_id, 0)
            }
            incidents.append(incident)
            already_fetched.append(report.get('id'))

    demisto.incidents(incidents)
    last_run = {
        'already_fetched': already_fetched,
    }
    demisto.setLastRun({'value': json.dumps(last_run)})


def search_reports_command() -> None:
    subject = demisto.getArg('subject')  # type: str
    url = demisto.getArg('url')  # type: str
    file_hash = demisto.getArg('file_hash')  # type: str
    reported_at, _ = parse_date_range(demisto.args().get('reported_at', DEFAULT_TIME_RANGE), to_timestamp=True)
    created_at, _ = parse_date_range(demisto.args().get('created_at', DEFAULT_TIME_RANGE), to_timestamp=True)
    reporter = demisto.getArg('reporter')  # type: str
    max_matches = int(demisto.getArg('max_matches'))  # type: int

    results = search_reports(subject, url, file_hash, reported_at, created_at, reporter, max_matches)
    if results:
        ec = {'Cofense.Report(val.id && val.id == obj.id)': snake_to_camel_keys(results)}
        hr = tableToMarkdown("Reports:", results, headerTransform=lambda h: h.replace("_", " ").title(),
                             removeNull=True)

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
                   max_matches=30) -> list:
    start_date, end_date = parse_date_range(demisto.args().get('reported_at', '2 months'), date_format=TIME_FORMAT)
    reports = http_request(url_suffix='processed_reports', params={'start_date': start_date,
                                                                   'end_date': end_date})
    if not isinstance(reports, list):
        reports = [reports]

    # if reporter:
    # reporters = get_all_reporters()

    matches = []

    for report in reports:
        if subject and subject != report.get('subject'):
            continue
        if url and url != report.get('url'):
            continue
        if reported_at and report.get('reported_at') and reported_at < date_to_timestamp(report.get('reported_at'),
                                                                                         TIME_FORMAT):  # todo: check
            continue
        if created_at and report.get('reported_at') and created_at < date_to_timestamp(report.get('created_at'),
                                                                                       TIME_FORMAT):
            continue
        if file_hash and file_hash != report.get('md5') and file_hash != report.get('sha256'):
            continue
        if reporter and int(reporter) != report.get('reporter_id'):
            # todo: check in all reporters demisto.results(json.dumps(reporters))
            continue

        matches.append(report)
        if len(matches) >= max_matches:
            break

    return matches


def get_reporter_command():
    reporter_id = demisto.getArg('reporter_id')  # type: str
    reporter = get_reporter(reporter_id)
    return_outputs(reporter, {})


def get_reporter(reporter_id):
    res = http_request(f'/reporters/{reporter_id}')
    if not isinstance(res, list):
        res = [res]
    reporter = res[0].get('email')

    return reporter


def get_all_reporters():
    start_time, _ = parse_date_range('1 day', date_format=TIME_FORMAT)
    res = http_request(f'/reporters', params={'start_date': start_time})
    if not isinstance(res, list):
        res = [res]
    reporter = res[0].get('email')

    return reporter


def get_attachment_command():
    attachment_id = demisto.getArg('attachment_id')  # type: str
    res = get_attachment(attachment_id)
    demisto.results(fileResult('Cofense Attachment', res.content))


def get_attachment(attachment_id):
    response = http_request(f'/attachment/{attachment_id}', params={'attachment_id': attachment_id}, raw_response=True)
    if not response.ok:
        return_error(f'Call to Cofense Triage failed [{response.status_code}]')
    else:
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

except Exception as ex:
    return_error(str(ex))
    raise

# ### BETA COMMAND ###

# def get_reports_command() -> None:
#     match_priority = demisto.getArg('match_priority')
#     category_id = demisto.getArg('category_id')
#     tags = demisto.getArg('tags')
#     start_date, end_date = parse_date_range(demisto.getArg('date_range'))
#     fields = argToList(demisto.getArg('fields'))
#
#     results = get_reports(match_priority, category_id, tags, fields, start_date, end_date)
#
#     ec = {'Cofense.Report(val.id && val.id == obj.id)': results}
#     hr = tableToMarkdown("Reports:", results, headerTransform=lambda h: h.replace("_", " ").title(), removeNull=True)
#     demisto.results({
#         'Type': entryTypes['note'],
#         'ContentsFormat': formats['markdown'],
#         'Contents': results if results else "no results were found",
#         'HumanReadable': hr,
#         'EntryContext': ec
#     })
#
#
# def get_reports(match_priority=None, category_id=None, tags=None, fields=None, start_date=None, end_date=None):
#     params = {
#         'category_id': category_id,
#         'fields[]': fields,
#         'match_priority': match_priority,
#         'tags': tags,
#         'start_date': start_date,
#         'end_date': end_date
#     }
#     return http_request(
#         url_suffix='processed_reports',
#         params=params
#     )


# def url_results_command() -> None:
#     start_date = demisto.getArg('start_date')
#     end_date = demisto.getArg('end_date')
#
#     results = url_results(start_date, end_date)
#     ec = {'Cofense.URL(val.id && val.id == obj.id)': results}
#
#     demisto.results(results)
#     demisto.results({
#         'Type': entryTypes['note'],
#         'ContentsFormat': formats['markdown'],
#         'Contents': results if results else "no results were found",
#         'HumanReadable': 'done',
#         'EntryContext': ec
#     })
#
#
# def url_results(start_date, end_date) -> dict:
#     params = {
#         'start_date': start_date,
#         'end_date': end_date
#     }
#     return http_request(
#         url_suffix='url_integration_results',
#         params=params
#     )


# def attachment_results_command() -> None:
#     start_date = demisto.getArg('start_date')
#     end_date = demisto.getArg('end_date')
#
#     results = attachment_results(start_date, end_date)
#     ec = {'Cofense.Attachment(val.id && val.id == obj.id)': results}
#
#     demisto.results(results)
#     demisto.results({
#         'Type': entryTypes['note'],
#         'ContentsFormat': formats['markdown'],
#         'Contents': results if results else "no results were found",
#         'HumanReadable': 'done',
#         'EntryContext': ec
#     })
#
#
# def attachment_results(start_date, end_date) -> dict:
#     params = {
#         'start_date': start_date,
#         'end_date': end_date
#     }
#     return http_request(
#         url_suffix='attachment_integration_results',
#         params=params
#     )

# def integration_search_command() -> None:
#     file_hash = demisto.getArg('file_hash')
#
#     results = integration_search(file_hash)
#     demisto.results({
#         'Type': entryTypes['note'],
#         'ContentsFormat': formats['markdown'],
#         'Contents': results,
#         'HumanReadable': 'done',
#         'EntryContext': results
#     })
#
#
# def integration_search(file_hash: str) -> dict:
#     hash_type = 'md5' if len(file_hash) == 32 else 'sha256'
#     return http_request(
#         url_suffix='integration_search',
#         params=((hash_type, file_hash),)
#     )
# elif demisto.command() == 'cofense-integration-search':
#     integration_search_command()
#
# elif demisto.command() == 'cofense-attachment-integration-results':
#     integration_search_command()
#
# elif demisto.command() == 'cofense-url-integration-results':
#     url_results_command()
