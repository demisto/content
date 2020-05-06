import demistomock as demisto
from CommonServerPython import *

from typing import Any, List, Dict
from io import BytesIO
from PIL import Image
from datetime import datetime
import functools
import json

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
    'email_attachments',
]


class TriageInstance:
    def __init__(self, *, host, token, user, disable_tls_verification=False):
        self.host = host
        self.token = token
        self.user = user
        self.disable_tls_verification = disable_tls_verification

    def request(self, endpoint, params=None, body=None, raw_response=False):
        """
        Make a request to the configured Triage instance and return the result.
        """
        # TODO automatic rate-limiting
        response = requests.get(
            self.api_url(endpoint),
            headers={
                "Authorization": f"Token token={self.user}:{self.token}",
                "Accept": "application/json",
            },
            params=params,
            data=body,
            verify=not self.disable_tls_verification,
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
        except json.decoder.JSONDecodeError as ex:
            demisto.debug(str(ex))
            return return_error(
                f"Could not parse result from Cofense Triage ({response.status_code})"
            )

    def api_url(self, endpoint):
        """Return a full URL for the configured Triage host and the specified endpoint"""

        endpoint = endpoint.lstrip("/")
        return f"{self.host}/api/public/v1/{endpoint}"


class TriageReport:
    """Class representing a Triage report by an end-user of a suspicious message"""

    def __init__(self, attrs):
        self.attrs = attrs

    @property
    def id(self):
        return self.attrs["id"]

    @property
    def date(self):
        return self.attrs.get("created_at")

    @property
    def category_name(self):
        return {
            1: 'Non-Malicious',
            2: 'Spam',
            3: 'Crimeware',
            4: 'Advanced Threats',
            5: 'Phishing Simulation',
            # TODO is this still complete?
        }.get(self.attrs["category_id"], "Unknown")

    @property
    def severity(self):
        # Demisto's severity levels are 4 - Critical, 3 - High, 2 - Medium, 1 - Low, 0 - Unknown
        return {
            1: 1,  # non malicious -> low
            2: 0,  # spam -> unknown
            3: 2,  # crimeware -> medium
            4: 2,  # advanced threats -> medium
            5: 1,  # phishing simulation -> low
        }.get(self.attrs["category_id"], 0)

    @property
    def report_body(self):
        return self.attrs.get("report_body")

    @property
    @functools.lru_cache()
    def reporter(self):
        return TriageReporter(self.attrs["reporter_id"])

    @property
    def terse_attrs(self):
        return {key: self.attrs[key] for key in self.attrs.keys() & TERSE_FIELDS}

    def to_json(self):
        """Flatten the Reporter object to a set of `reporter_` prefixed attributes"""
        return json.dumps(
            {
                **self.attrs,
                **{f"reporter_{k}": v for k, v in self.reporter.attrs.items()},
            }
        )

    @property
    @functools.lru_cache()
    def attachment(self):
        # TODO case-insensitive?
        if "HTML" in self.report_body:
            html_attachment = fileResult(
                filename=f"{self.id}-report.html", data=self.report_body.encode()
            )
            attachment = {
                "path": html_attachment.get("FileID"),
                "name": html_attachment.get("FileName"),
            }
            return attachment

        return None

    @classmethod
    def fetch(cls, report_id):
        return cls(TRIAGE_INSTANCE.request(f"reports/{report_id}")[0])


class TriageReporter:
    """Class representing an end user who has reported a suspicious message"""

    def __init__(self, reporter_id):
        """Fetch data for the first matching reporter from Triage"""
        matching_reporters = TRIAGE_INSTANCE.request(f"reporters/{reporter_id}")

        if matching_reporters:
            self.attrs = matching_reporters[0]
        else:
            self.attrs = {}

    def exists(self):
        return bool(self.attrs)


TRIAGE_INSTANCE = TriageInstance(
    host=demisto.getParam('host').rstrip('/'),
    token=demisto.getParam('token'),
    user=demisto.getParam('user'),
    disable_tls_verification=demisto.params().get('insecure', False),
)


def snake_to_camel_keys(snake_list: List[Dict]) -> List[Dict]:
    def snake_to_camel(snake_str) -> str:
        if snake_str == 'id':
            return 'ID'
        components = snake_str.split('_')
        return ''.join(x.title() for x in components)

    return [
        {snake_to_camel(k): v for k, v in snake_d.items()} for snake_d in snake_list
    ]


def split_snake(string: str) -> str:
    return string.replace("_", " ").title()


def parse_triage_date(date: str):
    return datetime.strptime(date, TIME_FORMAT)


def test_function() -> None:
    try:
        response = TRIAGE_INSTANCE.request("processed_reports")

        if response:
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

    triage_response = TRIAGE_INSTANCE.request(
        "processed_reports",
        params={
            "category_id": demisto.getParam("category_id"),
            "match_priority": demisto.getParam("match_priority"),
            "tags": demisto.getParam("tags"),
            "start_date": start_date,
        },
    )

    already_fetched = set(demisto.getLastRun().get('reports_fetched', []))

    triage_reports = [
        TriageReport(report)
        for report in triage_response
        if report["id"] not in already_fetched
    ]

    incidents = []
    for report in triage_reports:
        incident = {
            'name': f"cofense triage report {report.id}: {report.category_name}",
            'occurred': report.date,
            'rawJSON': report.to_json(),
            'severity': report.severity,
        }

        if report.attachment:
            incident['attachment'] = report.attachment

        incidents.append(incident)
        already_fetched.add(report.id)
        if len(incidents) >= max_fetch:
            break

    demisto.incidents(incidents)
    demisto.setLastRun({'reports_fetched': already_fetched})


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
    # TODO move to new TriageReportQuery (or similar) class
    params = {'start_date': datetime.strftime(reported_at, TIME_FORMAT)}
    reports = TRIAGE_INSTANCE.request("processed_reports", params=params)

    matches = []

    for report in reports:
        if subject and subject != report.get('report_subject'):
            # TODO do we really want to do exact string match here? not case-insensitive substring?
            continue
        if url and url not in [email_url["url"] for email_url in report["email_urls"]]:
            continue
        if (
            created_at
            and 'created_at' in report
            and created_at >= parse_triage_date(report['created_at'])
        ):
            continue
        if (
            file_hash
            and file_hash
            not in [
                attachment["email_attachment_payload"]["md5"]
                for attachment in report["email_attachments"]
            ]
            and file_hash
            not in [
                attachment["email_attachment_payload"]["sha256"]
                for attachment in report["email_attachments"]
            ]
        ):
            continue
        if reporter and int(reporter) != report.get('reporter_id'):
            continue

        if not verbose:
            # extract only relevant fields
            report = {key: report[key] for key in report.keys() & TERSE_FIELDS}

        matches.append(report)
        if len(matches) >= max_matches:
            break

    return matches


def get_all_reporters(time_frame) -> list:
    res = TRIAGE_INSTANCE.request("reporters", params={'start_date': time_frame})
    if not isinstance(res, list):
        res = [res]
    reporters = [reporter.get('email') for reporter in res]

    return reporters


def get_reporter_command() -> None:
    reporter_id = demisto.getArg('reporter_id')

    reporter = TriageReporter(reporter_id)

    if not reporter.exists():
        return return_outputs(
            readable_output="Could not find reporter with matching ID",
            outputs=reporter_id,
        )

    demisto.results(
        {
            "Type": entryTypes["note"],
            "ContentsFormat": formats["markdown"],
            "Contents": reporter.attrs,
            "HumanReadable": tableToMarkdown(
                "Reporter Results:",
                reporter.attrs,
                headerTransform=split_snake,
                removeNull=True
            ),
        }
    )


def get_attachment_command() -> None:
    # arguments importing
    attachment_id = demisto.getArg('attachment_id')  # type: str
    file_name = demisto.getArg('file_name') or attachment_id  # type: str

    res = TRIAGE_INSTANCE.request(f'attachment/{attachment_id}', raw_response=True)

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


def get_report_by_id_command() -> None:
    report_id = int(demisto.getArg('report_id'))  # type: int
    verbose = demisto.getArg('verbose') == "true"

    report = TriageReport.fetch(report_id)

    if not report:
        return return_error('Could not find report with matching ID')

    if verbose:
        report_attrs = report.attrs
    else:
        report_attrs = report.terse_attrs

    if report.attachment:
        demisto.results(
            {
                **report.attachment,
                **{"HumanReadable": "### Cofense HTML Report:\nHTML report download request has been completed"},
            }
        )
        del report_attrs["report_body"]

    hr = tableToMarkdown("Report Summary:", report_attrs, headerTransform=split_snake, removeNull=True)
    ec = {'Cofense.Report(val.ID && val.ID == obj.ID)': snake_to_camel_keys([report_attrs])}
    return_outputs(readable_output=hr, outputs=ec)


def get_threat_indicators_command() -> None:
    results = TRIAGE_INSTANCE.request(
        "triage_threat_indicators",
        params={
            "type": demisto.getArg("type"),
            "level": demisto.getArg("level"),
            "start_date": demisto.getArg("start_date"),
            "end_date": demisto.getArg("end_date"),
            "page": demisto.getArg("page"),
            "per_page": demisto.getArg("per_page"),
        },
    )

    if not results:
        return return_outputs("no results were found.", {})

    demisto.results(
        {
            "Type": entryTypes["note"],
            "ContentsFormat": formats["markdown"],
            "Contents": results if results else "no results were found",
            "HumanReadable": tableToMarkdown(
                "Threat Indicators:",
                results,
                headerTransform=split_snake,
                removeNull=True,
            ),
            "EntryContext": {
                "cofense.threatindicators(val.id && val.id == obj.id)": snake_to_camel_keys(
                    results
                )
            },
        }
    )


def get_report_png_by_id_command() -> None:
    report_id = int(demisto.getArg('report_id'))  # type: int
    set_white_bg = demisto.args().get('set_white_bg', 'False') == 'True'  # type: bool

    orig_png = get_report_png_by_id(report_id)

    if set_white_bg:
        inbuf = BytesIO()
        inbuf.write(orig_png)
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
        imgdata = orig_png

    cf_file = fileResult(
        "cofense_report_{}.png".format(report_id), imgdata, entryTypes["image"]
    )
    demisto.results(
        {
            "Type": entryTypes["image"],
            "ContentsFormat": formats["text"],
            "Contents": "Cofense: PNG of Report {}".format(report_id),
            "File": cf_file.get("File"),
            "FileID": cf_file.get("FileID"),
        }
    )


def get_report_png_by_id(report_id):
    """Fetch and return the PNG file associated with the specified report_id"""
    return TRIAGE_INSTANCE.request(
        f"reports/{report_id}.png", raw_response=True
    ).content


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
