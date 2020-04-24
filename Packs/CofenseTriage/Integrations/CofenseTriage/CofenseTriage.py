from typing import Any, List, Dict
from io import BytesIO
import requests
from PIL import Image

import demistomock as demisto
from CommonServerPython import *

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

TRIAGE_HOST = demisto.getParam('host').rstrip('/')
TOKEN = demisto.getParam('token')  # type: str
USER = demisto.getParam('user')  # type: str
USE_SSL = not demisto.params().get('insecure', False)  # type: bool

HEADERS = {
    "Authorization": f"Token token={USER}:{TOKEN}",
    "Accept": "application/json"
}  # type: dict
DEFAULT_TIME_RANGE = '7 days'  # type: str
TIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'  # type: str

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


def snake_to_camel_keys(snake_list: List[Dict]) -> List[Dict]:
    def snake_to_camel(snake_str) -> str:
        if snake_str == 'id':
            return 'ID'
        components = snake_str.split('_')
        return ''.join(x.title() for x in components)

    return [{snake_to_camel(k): v for k, v in snake_d.items()} for snake_d in snake_list]


def split_snake(string: str) -> str:
    return string.replace("_", " ").title()


def triage_request(endpoint, params=None, body=None, raw_response=False) -> Any:
    """
    Make a request to the configured Triage instance and return the result.
    """
    response = requests.get(
        triage_api_url(endpoint),
        headers=HEADERS,
        params=params,
        data=body,
        verify=USE_SSL,
    )

    if not response.ok:
        return return_error(
            f"Call to Cofense Triage failed ({response.status_code}): {response.text}"
        )

    if response.status_code == 206:
        # 206 indicates Partial Content. The reason will be in the warning header.
        demisto.debug(str(response.headers))

    if raw_response:
        # TODO refactor to get rid of this?
        return response

    if not response.text or response.text == "[]":
        return {}

    try:
        return response.json()
    except TypeError as ex:
        demisto.debug(str(ex))
        return return_error(
            f"Could not parse result from Cofense Triage ({response.status_code})"
        )


def test_function() -> None:
    try:
        response = requests.get(
            triage_api_url("processed_reports"),
            headers=HEADERS,
            params="",
            verify=USE_SSL,
        )

        if response.ok:
            # test fetching mechanism
            if demisto.params().get('isFetch'):
                fetch_reports()

            demisto.results('ok')

        else:
            return_error(
                "API call to Cofense Triage failed. Please check Server URL, or authentication "
                "related parameters.Status Code: {response.status_code} Reason: {response.reason}"
                f" [{response.status_code}] - {response.reason}"
            )

    except Exception as ex:
        demisto.debug(str(ex))
        return_error(repr(ex))


def fetch_reports() -> None:
    """Fetch up to `max_reports` reports since the last time the command was run. TODO date_range"""
    start_date, _ = parse_date_range(
        demisto.getParam('date_range'), date_format=TIME_FORMAT
    )
    max_fetch = int(demisto.getParam('max_fetch'))

    # TODO report should be an class
    reports = triage_request(
        "processed_reports",
        params={
            "category_id": demisto.getParam("category_id"),
            "match_priority": demisto.getParam("match_priority"),
            "tags": demisto.getParam("tags"),
            "start_date": start_date,
        },
    )

    already_fetched = set(demisto.getLastRun().get('reports_fetched', '[]'))

    incidents = []
    for report in reports:
        if "reporter_id" not in report:
            # TODO is this expected? debug output?
            continue

        if report["id"] in already_fetched:
            continue

        reporter_data = get_reporter_data(report["reporter_id"])
        for k, v in reporter_data.items():
            report_key = 'reporter_' + k
            report[report_key] = v

        report_id = report['id']
        report_body = report.pop('report_body')
        incident = {
            'name': f"cofense triage report {report_id}: {triage_report_category_name(report)}",
            'occurred': report.get('created_at'),
            'rawJSON': json.dumps(report),
            'severity': triage_report_severity(report)
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
        already_fetched.add(report_id)
        if len(incidents) >= max_fetch:
            break

    demisto.incidents(incidents)
    demisto.setLastRun({'reports_fetched': already_fetched})  # TODO does this have to be JSON?


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
    reports = triage_request("processed_reports", params=params)

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
    res = triage_request("reporters", params={'start_date': time_frame})
    if not isinstance(res, list):
        res = [res]
    reporters = [reporter.get('email') for reporter in res]

    return reporters


def get_reporter_command() -> None:
    # arguments importing
    reporter_id = demisto.getArg('reporter_id')  # type: str

    # running the API command
    reporter_data = get_reporter_data(reporter_id)

    if reporter_data:
        hr = tableToMarkdown("Reporter Results:", reporter_data, headerTransform=split_snake, removeNull=True)

        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['markdown'],
            'Contents': reporter_data if reporter_data else "no results were found",
            'HumanReadable': hr
        })
    else:
        readable_output = "Could not find reporter with matching ID"
        return_outputs(readable_output=readable_output, outputs=reporter_data)


def get_reporter_data(reporter_id) -> dict:
    """Fetch data for the first matching reporter from Triage"""
    res = triage_request(f"reporters/{reporter_id}")
    if not isinstance(res, list):
        res = [res]
    reporter = res[0]

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
    response = triage_request(f'attachment/{attachment_id}', params={'attachment_id': attachment_id}, raw_response=True)
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
    #FIXME    res['reporter'] = get_reporter(res.get('reporter_id'))  # enrich: id -> email
        hr = tableToMarkdown("Report Summary:", res, headerTransform=split_snake, removeNull=True)
        ec = {'Cofense.Report(val.ID && val.ID == obj.ID)': snake_to_camel_keys([res])}
        return_outputs(readable_output=hr, outputs=ec)

    else:
        return_error('Could not find report with matching ID')


def get_threat_indicators(indicator_type=None, level=None, start_date=None, end_date=None, page=None, per_page=None) -> list:
    params = {}
    params['type'] = indicator_type
    params['level'] = level
    params['start_date'] = start_date
    params['end_date'] = end_date
    params['page'] = page
    params['per_page'] = per_page
    results = triage_request("triage_threat_indicators", params=params)

    if not isinstance(results, list):
        results = [results]

    return results


def get_threat_indicators_command() -> None:
    demisto.log('testing')
    # arguments importing
    indicator_type = demisto.getArg('type')
    level = demisto.getArg('level')
    start_date = demisto.getArg('start_date')
    end_date = demisto.getArg('end_date')
    page = demisto.getArg('page')
    per_page = demisto.getArg('per_page')

    results = get_threat_indicators(
        indicator_type, level, start_date, end_date, page, per_page
    )
    demisto.log(str(results))


# parsing outputs
    if results:
        ec = {'Cofense.ThreatIndicators(val.ID && val.ID == obj.ID)': snake_to_camel_keys(results)}
        hr = tableToMarkdown(
            "Threat Indicators:", results, headerTransform=split_snake, removeNull=True
        )

        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['markdown'],
            'Contents': results if results else "no results were found",
            'HumanReadable': hr,
            'EntryContext': ec
        })
    else:
        return_outputs("no results were found.", {})


def get_report_png_by_id_command() -> None:
    report_id = int(demisto.getArg('report_id'))  # type: int
    set_white_bg = demisto.args().get('set_white_bg', 'False') == 'True'  # type: bool

    res = get_report_png_by_id(report_id)

    # Convert the background from transparent to white (used for dark theme)

    imgdata = None
    if set_white_bg:
        inbuf = BytesIO()
        inbuf.write(res.content)
        inbuf.seek(0)

        image = Image.open(inbuf)
        canvas = Image.new(
            'RGBA', image.size, (255, 255, 255, 255)
        )  # Empty canvas colour (r,g,b,a)
        canvas.paste(
            image, mask=image
        )  # Paste the image onto the canvas, using it's alpha channel as mask

        outbuf = BytesIO()
        canvas.save(outbuf, format="PNG")
        outbuf.seek(0)

        imgdata = outbuf.getvalue()
    else:
        imgdata = res.content

    cf_file = fileResult('cofense_report_{}.png'.format(report_id), imgdata, entryTypes['image'])
    demisto.results({
        'Type': entryTypes['image'],
        'ContentsFormat': formats['text'],
        'Contents': 'Cofense: PNG of Report {}'.format(report_id),
        'File': cf_file.get('File'),
        'FileID': cf_file.get('FileID')
    })


def get_report_png_by_id(report_id):
    response = triage_request(
        f'reports/{report_id}.png', params={'report_id': report_id}, raw_response=True
    )
    if not response.ok:
        return_error(f'Call to Cofense Triage failed [{response.status_code}]')
    else:
        return response


def parse_report_body(report) -> None:
    if 'report_body' in report and 'HTML' in report['report_body']:
        attachment = fileResult(
            filename=f'{report.get("id")}-report.html',
            data=report.get('report_body').encode(),
        )
        attachment[
            'HumanReadable'
        ] = '### Cofense HTML Report:\nHTML report download request has been completed'
        demisto.results(attachment)
        del report['report_body']


def get_report_by_id(report_id):
    """Fetch a report from Triage by report_id"""

    return triage_request(f"reports/{report_id}", params={'report_id': report_id})


def triage_api_url(endpoint):
    """Return a full URL for the configured Triage host and the specified endpoint"""

    endpoint = endpoint.ltrip("/")
    return f"{TRIAGE_HOST}/api/public/v1/{endpoint}"


def triage_report_category_name(report):
    """Return the human-readable name of the category the given report belongs to"""

    category_id = report.get("category_id")
    return {
        1: "Non-Malicious",
        2: "Spam",
        3: "Crimeware",
        4: "Advanced Threats",
        6: "Phishing Simulation",
    }.get(category_id, "Unknown")


def triage_report_severity(report):
    """Return the human-readable name of the severity. Severity is a function of category."""

    category_id = report.get("category_id")
    # Demisto's severity levels are 4 - Critical, 3 - High, 2 - Medium, 1 - Low, 0 - Unknown
    return {
        1: 1,  # non malicious -> low
        2: 0,  # spam -> unknown
        3: 2,  # crimeware -> medium
        4: 2,  # advanced threats -> medium
        5: 1,  # phishing simulation -> low
    }.get(category_id, 0)


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

    elif demisto.command() == 'cofense-get-report-png-by-id':
        get_report_png_by_id_command()

    elif demisto.command() == 'cofense-get-threat-indicators':
        get_threat_indicators_command()

except Exception as e:
    return_error(str(e))
    raise
