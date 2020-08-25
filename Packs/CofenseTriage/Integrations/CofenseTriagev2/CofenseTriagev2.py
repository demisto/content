import demistomock as demisto
from CommonServerPython import *

from typing import List, Dict
from io import BytesIO
from PIL import Image
from datetime import datetime
from datetime import timezone
import functools
import json

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


class TriageRequestFailedError(Exception):
    """Triage responded with something other than a normal 200 response"""

    def __init__(self, status_code, message):
        super().__init__(self, status_code, message)
        self.status_code = status_code
        self.message = message

    def __str__(self):
        return f"Call to Cofense Triage failed ({self.status_code}): {self.message}"


class TriageRequestEmptyResponse(Exception):
    """Triage responded without error, but the result set was unexpectedly empty"""

    def __init__(self, record_id, record_type):
        super().__init__(self, record_id, record_type)
        self.record_id = record_id
        self.record_type = record_type

    def __str__(self):
        return f"Could not find a {self.record_type} with id {self.record_id}"


class TriageInstance:
    def __init__(
        self, *, host, token, user, disable_tls_verification=False, demisto_params
    ):
        self.host = host
        self.token = token
        self.user = user
        self.disable_tls_verification = disable_tls_verification
        self.demisto_params = demisto_params

    def request(self, endpoint, params=None, body=None, raw_response=False):
        """
        Make a request to the configured Triage instance and return the result.
        """
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
            raise TriageRequestFailedError(response.status_code, response.text)

        if response.status_code == 206:
            # 206 indicates Partial Content. The reason will be in the warning header.
            demisto.debug(str(response.headers))

        if raw_response:
            return response

        if not response.text or response.text == "[]":
            return {}

        try:
            return response.json()
        except json.decoder.JSONDecodeError as ex:
            demisto.debug(str(ex))
            raise TriageRequestFailedError(
                response.status_code, "Could not parse result from Cofense Triage"
            )

    def api_url(self, endpoint):
        """Return a full URL for the configured Triage host and the specified endpoint"""

        endpoint = endpoint.lstrip("/")
        return f"{self.host}/api/public/v1/{endpoint}"

    def get_demisto_param(self, name):
        return self.demisto_params[name]


class TriageReport:
    """
    Class representing a Triage report by an end-user of a suspicious message

    Model associations:
    TriageReporter - The user who reported the message. A TriageReport has exactly one TriageReporter.
    """

    def __init__(self, triage_instance, attrs):
        self.triage_instance = triage_instance
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

    @property  # type: ignore
    @functools.lru_cache()
    def reporter(self):
        return TriageReporter(self.triage_instance, self.attrs["reporter_id"])

    @property
    def terse_attrs(self):
        return {key: self.attrs[key] for key in self.attrs.keys() & TERSE_FIELDS}

    def to_json(self):
        """Flatten the Reporter object to a set of `reporter_` prefixed attributes"""
        return json.dumps(
            {
                **self.attrs,
                **{f"reporter_{k}": v for k, v in self.reporter.attrs.items()},  # type: ignore
            }
        )

    @property  # type: ignore
    @functools.lru_cache()
    def attachment(self):
        if "HTML" in self.report_body:
            html_attachment = fileResult(
                filename=f"{self.id}-report.html", data=self.report_body.encode()
            )
            attachment = {
                "path": html_attachment.get("FileID"),
                "name": html_attachment.get("File"),
            }
            return attachment

        return None

    @classmethod
    def fetch(cls, triage_instance, report_id):
        return cls(triage_instance, triage_instance.request(f"reports/{report_id}")[0])


class TriageReporter:
    """
    Class representing an end user who has reported a suspicious message

    Model associations:
    TriageReport - A reporter submitted by this user. A TriageReporter may have many TriageReports.
    """

    def __init__(self, triage_instance, reporter_id):
        """Fetch data for the first matching reporter from Triage"""
        matching_reporters = triage_instance.request(f"reporters/{reporter_id}")

        if matching_reporters:
            self.attrs = matching_reporters[0]
        else:
            self.attrs = {}

    def exists(self):
        return bool(self.attrs)


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
    # datetime from isoformat only supports a subset of ISO-8601.
    # See https://discuss.python.org/t/parse-z-timezone-suffix-in-datetime/2220
    if date.endswith('Z'):
        date = date[:-1] + '+00:00'
    return datetime.fromisoformat(date)


def test_function(triage_instance) -> None:
    try:
        response = triage_instance.request("processed_reports")

        if response:
            demisto.results('ok')
        else:
            raise TriageRequestFailedError(
                response.status_code,
                "API call to Cofense Triage failed. Please check integration configuration.\n"
                "Reason: {response.reason}",
            )
    except Exception as err:
        demisto.debug(str(err))
        raise err


def fetch_reports(triage_instance) -> None:
    """Fetch up to `max_reports` reports since the last time the command was run."""
    start_date = triage_instance.get_demisto_param("start_date")
    max_fetch = triage_instance.get_demisto_param("max_fetch")

    triage_response = triage_instance.request(
        "processed_reports",
        params={
            "category_id": triage_instance.get_demisto_param("category_id"),
            "match_priority": triage_instance.get_demisto_param("match_priority"),
            "tags": triage_instance.get_demisto_param("tags"),
            "start_date": start_date,
        },
    )

    already_fetched = set(json.loads(demisto.getLastRun().get("reports_fetched", "[]")))

    triage_reports = [
        TriageReport(triage_instance, report)
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
            incident['attachment'] = [report.attachment]

        incidents.append(incident)
        already_fetched.add(report.id)
        if len(incidents) >= max_fetch:
            break

    demisto.incidents(incidents)
    demisto.setLastRun({"reports_fetched": json.dumps(list(already_fetched))})


def search_reports_command(triage_instance) -> None:
    subject = demisto.getArg('subject')  # type: str
    url = demisto.getArg('url')  # type: str
    file_hash = demisto.getArg('file_hash')  # type: str
    reported_at = parse_date_range(demisto.args().get('reported_at', '7 days'))[
        0
    ].replace(tzinfo=timezone.utc)
    created_at = parse_date_range(demisto.args().get('created_at', '7 days'))[
        0
    ].replace(tzinfo=timezone.utc)
    reporter = demisto.getArg('reporter')  # type: str
    max_matches = int(demisto.getArg('max_matches'))  # type: int
    verbose = demisto.getArg('verbose') == "true"

    results = search_reports(
        triage_instance,
        subject,
        url,
        file_hash,
        reported_at,
        created_at,
        reporter,
        verbose,
        max_matches,
    )

    if results:
        ec = {
            "Cofense.Report(val.ID && val.ID == obj.ID)": snake_to_camel_keys(results)
        }
        hr = tableToMarkdown(
            "Reports:", results, headerTransform=split_snake, removeNull=True
        )

        return_outputs(hr, ec, results)
    else:
        return_outputs("no results were found.", {}, {})


def search_reports(
    triage_instance,
    subject=None,
    url=None,
    file_hash=None,
    reported_at=None,
    created_at=None,
    reporter=None,
    verbose=False,
    max_matches=30,
) -> list:
    params = {'start_date': reported_at}
    reports = triage_instance.request("processed_reports", params=params)

    matches = []

    for report in reports:
        if subject and subject != report.get('report_subject'):
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


def get_all_reporters(triage_instance, time_frame) -> list:
    res = triage_instance.request("reporters", params={'start_date': time_frame})
    if not isinstance(res, list):
        res = [res]
    reporters = [reporter.get('email') for reporter in res]

    return reporters


def get_reporter_command(triage_instance) -> None:
    reporter_id = demisto.getArg('reporter_id')

    reporter = TriageReporter(triage_instance, reporter_id)

    if not reporter.exists():
        return return_outputs(
            readable_output="Could not find reporter with matching ID",
            outputs=reporter_id,
            raw_response=json.dumps(reporter.attrs)
        )

    camel_case_attrs = snake_to_camel_keys([reporter.attrs])[0]
    return_outputs(
        outputs={"Cofense.Reporter(val.Id && val.Id == obj.Id)": camel_case_attrs},
        readable_output=tableToMarkdown(
            "Reporter Results:",
            reporter.attrs,
            headerTransform=split_snake,
            removeNull=True,
        ),
        raw_response=json.dumps(reporter.attrs)
    )


def get_attachment_command(triage_instance) -> None:
    attachment_id = str(demisto.getArg('attachment_id'))  # type: str
    file_name = demisto.getArg('file_name') or attachment_id  # type: str

    res = triage_instance.request(f'attachment/{attachment_id}', raw_response=True)

    result = fileResult(file_name, res.content)
    demisto.results(result)


def get_report_by_id_command(triage_instance) -> None:
    report_id = int(demisto.getArg('report_id'))  # type: int
    verbose = demisto.getArg('verbose') == "true"

    report = TriageReport.fetch(triage_instance, report_id)

    if not report:
        raise TriageRequestEmptyResponse(report_id, "Report")

    if verbose:
        report_attrs = report.attrs
    else:
        report_attrs = report.terse_attrs

    if report.attachment:
        demisto.results(
            {
                **report.attachment,
                **{
                    "HumanReadable": "### Cofense HTML Report:\nHTML report download request has been completed"
                },
            }
        )
        del report_attrs["report_body"]

    hr = tableToMarkdown(
        "Report Summary:", report_attrs, headerTransform=split_snake, removeNull=True
    )
    ec = {
        "Cofense.Report(val.ID && val.ID == obj.ID)": snake_to_camel_keys(
            [report_attrs]
        )
    }
    return_outputs(readable_output=hr, outputs=ec, raw_response=report.to_json())


def get_threat_indicators_command(triage_instance) -> None:
    results = triage_instance.request(
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
                "Cofense.ThreatIndicators(val.ID && val.ID == obj.ID)": snake_to_camel_keys(
                    results
                )
            },
        }
    )


def get_report_png_by_id_command(triage_instance) -> None:
    report_id = int(demisto.getArg('report_id'))  # type: int
    set_white_bg = demisto.args().get('set_white_bg', 'False') == 'True'  # type: bool

    orig_png = get_report_png_by_id(triage_instance, report_id)

    if set_white_bg:
        in_buffer = BytesIO()
        in_buffer.write(orig_png)
        in_buffer.seek(0)

        image = Image.open(in_buffer)
        canvas = Image.new(
            'RGBA', image.size, (255, 255, 255, 255)
        )  # Empty canvas colour (r,g,b,a)
        canvas.paste(
            image, mask=image
        )  # Paste the image onto the canvas, using it's alpha channel as mask

        out_buffer = BytesIO()
        canvas.save(out_buffer, format="PNG")
        out_buffer.seek(0)

        image_data = out_buffer.getvalue()
    else:
        image_data = orig_png

    cf_file = fileResult(
        "cofense_report_{}.png".format(report_id), image_data, entryTypes["image"]
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


def get_report_png_by_id(triage_instance, report_id):
    """Fetch and return the PNG file associated with the specified report_id"""
    return triage_instance.request(
        f"reports/{report_id}.png", raw_response=True
    ).content


def main():
    try:
        handle_proxy()

        demisto_params = {
            "start_date": parse_date_range(demisto.getParam('date_range'))[
                0
            ].isoformat(),
            "max_fetch": int(demisto.getParam('max_fetch')),
            "category_id": demisto.getParam("category_id"),
            "match_priority": demisto.getParam("match_priority"),
            "tags": demisto.getParam("tags"),
        }

        triage_instance = TriageInstance(
            host=demisto.getParam("host").rstrip("/") if demisto.getParam("host") else "",
            token=demisto.getParam("token"),
            user=demisto.getParam("user"),
            disable_tls_verification=demisto.params().get("insecure", False),
            demisto_params=demisto_params,
        )

        if demisto.command() == "test-module":
            test_function(triage_instance)

        if demisto.command() == "fetch-incidents":
            fetch_reports(triage_instance)

        elif demisto.command() == "cofense-search-reports":
            search_reports_command(triage_instance)

        elif demisto.command() == "cofense-get-attachment":
            get_attachment_command(triage_instance)

        elif demisto.command() == "cofense-get-reporter":
            get_reporter_command(triage_instance)

        elif demisto.command() == "cofense-get-report-by-id":
            get_report_by_id_command(triage_instance)

        elif demisto.command() == "cofense-get-report-png-by-id":
            get_report_png_by_id_command(triage_instance)

        elif demisto.command() == "cofense-get-threat-indicators":
            get_threat_indicators_command(triage_instance)

    except Exception as e:
        return_error(str(e))
        raise


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
