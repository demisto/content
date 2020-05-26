import pytest
from freezegun import freeze_time
import datetime
from unittest.mock import patch


def fixture_from_file(fname):
    with open(f"test/fixtures/{fname}", "r") as file:
        return file.read()


DEMISTO_ARGS = {}


def set_demisto_arg(name, value):
    DEMISTO_ARGS[name] = value


def set_demisto_args(args):
    for name, value in args.items():
        set_demisto_arg(name, value)


def get_demisto_arg(name):
    if name in DEMISTO_ARGS:
        return DEMISTO_ARGS[name]
    raise Exception(
        f'Test setup did not specify a Demisto argument named {name}. Use `set_demisto_arg("{name}", "value")`.'
    )


set_demisto_arg("host", "https://some-triage-host/")
set_demisto_arg("token", "api_token")
set_demisto_arg("user", "user")
patch("demistomock.getParam", get_demisto_arg)  # args ≡ params in tests

from CofenseTriage2 import CofenseTriage  # noqa: 402
from CofenseTriage2.CofenseTriage import parse_triage_date  # noqa: 402


@pytest.fixture(autouse=True)
def stub_demisto_setup(mocker):
    mocker.patch("CofenseTriage2.CofenseTriage.return_error")
    mocker.patch("CofenseTriage2.CofenseTriage.fileResult")
    mocker.patch("demistomock.getArg", get_demisto_arg)
    mocker.patch("demistomock.getParam", get_demisto_arg)  # args ≡ params in tests
    mocker.patch("demistomock.results")
    mocker.patch("demistomock.incidents")
    mocker.patch("demistomock.setLastRun")


class TestCofenseTriage:
    def test_test_function(self, requests_mock):
        requests_mock.get(
            "https://some-triage-host/api/public/v1/processed_reports",
            text=fixture_from_file("processed_reports.json"),
        )

        CofenseTriage.test_function()

        CofenseTriage.demisto.results.assert_called_once_with("ok")

    def test_test_function_error(self, requests_mock):
        requests_mock.get(
            "https://some-triage-host/api/public/v1/processed_reports",
            status_code=404,
            text=fixture_from_file("processed_reports.json"),
        )

        CofenseTriage.test_function()

        CofenseTriage.return_error.assert_called_once()

    @freeze_time("2000-10-31")
    def test_fetch_reports(self, mocker, requests_mock):
        set_demisto_arg("max_fetch", 10)
        set_demisto_arg("date_range", "1 day")
        set_demisto_arg("category_id", 5)
        set_demisto_arg("match_priority", 2)
        set_demisto_arg("tags", "")
        requests_mock.get(
            "https://some-triage-host/api/public/v1/processed_reports?category_id=5&match_priority=2&tags=&start_date=2000-10-30T00%3A00%3A00.000000Z", # noqa: 501
            text=fixture_from_file("processed_reports.json"),
        )
        requests_mock.get(
            "https://some-triage-host/api/public/v1/reporters/5331",
            text=fixture_from_file("reporters.json"),
        )
        mocker.patch(
            "CofenseTriage2.CofenseTriage.fileResult",
            lambda filename, data: {"FileID": "file_id", "FileName": "file_name"},
        )

        CofenseTriage.fetch_reports()

        demisto_incidents = CofenseTriage.demisto.incidents.call_args_list[0][0][0]
        assert len(demisto_incidents) == 2
        assert (
            demisto_incidents[0]["name"]
            == "cofense triage report 13363: Phishing Simulation"
        )
        assert demisto_incidents[0]["occurred"] == "2020-03-19T16:43:09.715Z"
        assert demisto_incidents[0]["severity"] == 1
        assert len(demisto_incidents[0]["rawJSON"]) == 1931

        assert demisto_incidents[1]["attachment"] == [
            {"name": "file_name", "path": "file_id"}
        ]

        CofenseTriage.demisto.setLastRun.assert_called_once_with(
            {"reports_fetched": "[13392, 13363]"}
        )

    @freeze_time("2000-10-31")
    def test_fetch_reports_already_fetched(self, mocker, requests_mock):
        set_demisto_args(
            {
                "max_fetch": 10,
                "date_range": "1 day",
                "category_id": 5,
                "match_priority": 2,
                "tags": "",
            }
        )
        requests_mock.get(
            "https://some-triage-host/api/public/v1/processed_reports?category_id=5&match_priority=2&tags=&start_date=2000-10-30T00%3A00%3A00.000000Z", # noqa: 501
            text=fixture_from_file("processed_reports.json"),
        )
        requests_mock.get(
            "https://some-triage-host/api/public/v1/reporters/5331",
            text=fixture_from_file("reporters.json"),
        )
        mocker.patch("demistomock.getLastRun", lambda: {"reports_fetched": "[13363]"})

        CofenseTriage.fetch_reports()

        demisto_incidents = CofenseTriage.demisto.incidents.call_args_list[0][0][0]
        assert len(demisto_incidents) == 1
        assert demisto_incidents[0]["name"] == "cofense triage report 13392: Crimeware"

        CofenseTriage.demisto.setLastRun.assert_called_once_with(
            {"reports_fetched": "[13392, 13363]"}
        )

    @freeze_time("2000-10-31")
    def test_search_reports_command(self, requests_mock):
        set_demisto_arg("subject", "suspicious subject")
        set_demisto_arg("url", "")
        set_demisto_arg("file_hash", "")
        set_demisto_arg("reporter", "")
        set_demisto_arg("max_matches", 10)
        set_demisto_arg("verbose", "")
        requests_mock.get(
            "https://some-triage-host/api/public/v1/processed_reports?start_date=2000-10-24T00%3A00%3A00.000000Z", # noqa: 501
            text=fixture_from_file("processed_reports.json"),
        )

        CofenseTriage.search_reports_command()

        demisto_results = CofenseTriage.demisto.results.call_args_list[0][0]
        assert len(demisto_results) == 1
        assert demisto_results[0]["HumanReadable"] == (
            "### Reports:\n"
            "|Category Id|Created At|Email Attachments|Id|Location|Match Priority|Md5|Report Body|Report Subject|Reported At|Reporter Id|Sha256|\n" # noqa: 501
            "|---|---|---|---|---|---|---|---|---|---|---|---|\n" # noqa: 501
            "| 5 | 2020-03-19T16:43:09.715Z | {'id': 18054, 'report_id': 13363, 'decoded_filename': 'image003.png', 'content_type': 'image/png; name=image003.png', 'size_in_bytes': 7286, 'email_attachment_payload': {'id': 7082, 'md5': '123', 'sha256': '1234', 'mime_type': 'image/png; charset=binary'}} | 13363 | Processed | 1 | 111 | From: Sender <sender@example.com><br>Reply-To: \"sender@example.com\" <sender@example.com><br>Date: Wednesday, March 18, 2020 at 3:34 PM<br>To: recipient@example.com<br>Subject: suspicious subject<br>click on this link! trust me! <a href=\"http://example.com/malicious\">here</a> | suspicious subject | 2020-03-19T16:42:22.000Z | 5331 | 222 |\n" # noqa: 501
        )

    @freeze_time("2000-10-31")
    def test_search_reports_command_not_found(self, requests_mock):
        set_demisto_arg("subject", "my great subject")
        set_demisto_arg("url", "my-great-url")
        set_demisto_arg("file_hash", "")
        set_demisto_arg("reporter", "")
        set_demisto_arg("max_matches", 10)
        set_demisto_arg("verbose", "")
        requests_mock.get(
            "https://some-triage-host/api/public/v1/processed_reports?start_date=2000-10-24T00%3A00%3A00.000000Z", # noqa: 501
            text=fixture_from_file("processed_reports.json"),
        )

        CofenseTriage.search_reports_command()

        demisto_results = CofenseTriage.demisto.results.call_args_list[0][0]
        assert len(demisto_results) == 1
        assert demisto_results[0]["HumanReadable"] == "no results were found."

    @freeze_time("2000-10-31")
    @pytest.mark.parametrize(
        "filter_attrs, expected_found_report_ids",
        [
            ({"subject": "suspicious subject"}, [13363]),
            ({"subject": "suspicious"}, []),
            ({"subject": "nah"}, []),
            ({"url": "http://example.com/malicious"}, [13363]),
            ({"url": "example.com"}, []),
            ({"url": "nah"}, []),
            ({"created_at": parse_triage_date("2055-03-19T16:43:09.715Z")}, []),
            (
                {"created_at": parse_triage_date("1999-03-19T16:43:09.715Z")},
                [13363, 13392],
            ),
            ({"file_hash": "123"}, [13363]),
            ({"file_hash": "1234"}, [13363]),
            ({"file_hash": "5"}, []),
            ({"reporter": "5331"}, [13363, 13392]),
            ({"reporter": "2000"}, []),
        ],
    )
    def test_search_reports_filtering(
        self, requests_mock, filter_attrs, expected_found_report_ids
    ):
        requests_mock.get(
            "https://some-triage-host/api/public/v1/processed_reports?start_date=2000-10-31T00%3A00%3A00.000000Z", # noqa: 501
            text=fixture_from_file("processed_reports.json"),
        )

        found_reports = CofenseTriage.search_reports(
            **filter_attrs, reported_at=datetime.datetime.now()
        )
        assert [report["id"] for report in found_reports] == expected_found_report_ids

    def test_get_attachment_command(self, mocker, requests_mock):
        set_demisto_arg("attachment_id", "5")
        set_demisto_arg("file_name", "my_great_file")
        requests_mock.get(
            "https://some-triage-host/api/public/v1/attachment/5",
            text=fixture_from_file("attachment.txt"),
        )

        CofenseTriage.get_attachment_command()

        CofenseTriage.fileResult.assert_called_with(
            "my_great_file", b"A Great Attachment\n"
        )
        CofenseTriage.demisto.results.assert_has_calls(
            [
                mocker.call(CofenseTriage.fileResult()),
                mocker.call(
                    {
                        "Type": 1,
                        "ContentsFormat": "markdown",
                        "Contents": "",
                        "HumanReadable": "",
                        "EntryContext": {
                            "Cofense.Attachment(val.ID == obj.ID)": {"ID": "5"}
                        },
                    }
                ),
            ]
        )

    def test_get_reporter_command(self, requests_mock):
        set_demisto_arg("reporter_id", "5")
        requests_mock.get(
            "https://some-triage-host/api/public/v1/reporters/5",
            text=fixture_from_file("reporters.json"),
        )

        CofenseTriage.get_reporter_command()

        demisto_results = CofenseTriage.demisto.results.call_args_list[0][0]
        assert demisto_results[0]["HumanReadable"] == (
            "### Reporter Results:\n"
            "|Created At|Credibility Score|Email|Id|Last Reported At|Reports Count|Updated At|Vip|\n"
            "|---|---|---|---|---|---|---|---|\n"
            "| 2019-04-12T02:58:17.401Z | 0 | reporter1@example.com | 111 | 2016-02-18T00:24:45.000Z | 3 | 2019-04-12T02:59:22.287Z | false |\n" # noqa: 501
        )
        assert demisto_results[0]["Contents"] == {
            "id": 111,
            "email": "reporter1@example.com",
            "created_at": "2019-04-12T02:58:17.401Z",
            "updated_at": "2019-04-12T02:59:22.287Z",
            "credibility_score": 0,
            "reports_count": 3,
            "last_reported_at": "2016-02-18T00:24:45.000Z",
            "vip": False,
        }

    def test_get_report_by_id_command(self, requests_mock):
        set_demisto_arg("report_id", "6")
        set_demisto_arg("verbose", "false")
        requests_mock.get(
            "https://some-triage-host/api/public/v1/reports/6",
            text=fixture_from_file("single_report.json"),
        )
        requests_mock.get(
            "https://some-triage-host/api/public/v1/reporters/5",
            text=fixture_from_file("reporters.json"),
        )

        CofenseTriage.get_report_by_id_command()

        demisto_results = CofenseTriage.demisto.results.call_args_list[0][0]
        assert demisto_results[0]["HumanReadable"] == (
            "### Report Summary:\n"
            "|Category Id|Created At|Email Attachments|Id|Location|Match Priority|Md5|Report Body|Report Subject|Reported At|Reporter Id|Sha256|\n" # noqa: 501
            "|---|---|---|---|---|---|---|---|---|---|---|---|\n"
            "| 7 | 2020-03-19T16:43:09.715Z | {'id': 18054, 'report_id': 13363, 'decoded_filename': 'image003.png', 'content_type': 'image/png; name=image003.png', 'size_in_bytes': 7286, 'email_attachment_payload': {'id': 7082, 'md5': '123', 'sha256': '1234', 'mime_type': 'image/png; charset=binary'}} | 13363 | Processed | 1 | 111 | From: Sender <sender@example.com><br>Reply-To: \"sender@example.com\" <sender@example.com><br>Date: Wednesday, March 18, 2020 at 3:34 PM<br>To: recipient@example.com<br>Subject: suspicious subject<br>click on this link! trust me! <a href=\"http://example.com/malicious\">here</a> | suspicious subject | 2020-03-19T16:42:22.000Z | 5331 | 222 |\n" # noqa: 501
        )

    def test_get_report_by_id_command_with_attachment(self, requests_mock):
        set_demisto_arg("report_id", "6")
        set_demisto_arg("verbose", "false")
        requests_mock.get(
            "https://some-triage-host/api/public/v1/reports/6",
            text=fixture_from_file("single_report_with_attachment.json"),
        )
        requests_mock.get(
            "https://some-triage-host/api/public/v1/reporters/5",
            text=fixture_from_file("reporters.json"),
        )

        CofenseTriage.get_report_by_id_command()

        demisto_results = CofenseTriage.demisto.results.call_args_list
        assert demisto_results[0][0][0]["HumanReadable"] == (
            "### Cofense HTML Report:\n"
            "HTML report download request has been completed"
        )
        assert demisto_results[1][0][0]["HumanReadable"] == (
            "### Report Summary:\n"
            "|Category Id|Created At|Email Attachments|Id|Location|Match Priority|Md5|Report Subject|Reported At|Reporter Id|Sha256|\n" # noqa: 501
            "|---|---|---|---|---|---|---|---|---|---|---|\n"
            "| 7 | 2020-03-19T16:43:09.715Z | {'id': 18054, 'report_id': 13363, 'decoded_filename': 'image003.png', 'content_type': 'image/png; name=image003.png', 'size_in_bytes': 7286, 'email_attachment_payload': {'id': 7082, 'md5': '123', 'sha256': '1234', 'mime_type': 'image/png; charset=binary'}} | 13363 | Processed | 1 | 111 | suspicious subject | 2020-03-19T16:42:22.000Z | 5331 | 222 |\n" # noqa: 501
        )

    def test_get_all_reporters(self, requests_mock):
        requests_mock.get(
            "https://some-triage-host/api/public/v1/reporters?start_date=1995-01-01",
            text=fixture_from_file("reporters.json"),
        )

        reporters = CofenseTriage.get_all_reporters("1995-01-01")

        assert reporters == [
            "reporter1@example.com",
            "reporter2@example.com",
        ]

    def test_get_threat_indicators_command(self, requests_mock):
        set_demisto_arg("type", "what")
        set_demisto_arg("level", "what")
        set_demisto_arg("start_date", "what")
        set_demisto_arg("end_date", "what")
        set_demisto_arg("page", "what")
        set_demisto_arg("per_page", "what")
        requests_mock.get(
            "https://some-triage-host/api/public/v1/triage_threat_indicators?type=what&level=what&start_date=what&end_date=what&page=what&per_page=what", # noqa: 501
            text=fixture_from_file("threat_indicators.json"),
        )

        CofenseTriage.get_threat_indicators_command()

        demisto_results = CofenseTriage.demisto.results.call_args_list[0][0]
        assert len(demisto_results) == 1
        assert demisto_results[0]["HumanReadable"] == (
            "### Threat Indicators:\n"
            "|Created At|Id|Operator Id|Report Id|Threat Key|Threat Level|Threat Value|\n"
            "|---|---|---|---|---|---|---|\n"
            "| 2020-03-16T17:39:14.579Z | 37 | 2 | 13353 | Domain | Malicious | malicious.example.com |\n"
        )

    def test_get_threat_indicators_command_not_found(self, requests_mock):
        set_demisto_arg("type", "what")
        set_demisto_arg("level", "what")
        set_demisto_arg("start_date", "what")
        set_demisto_arg("end_date", "what")
        set_demisto_arg("page", "what")
        set_demisto_arg("per_page", "what")
        requests_mock.get(
            "https://some-triage-host/api/public/v1/triage_threat_indicators?type=what&level=what&start_date=what&end_date=what&page=what&per_page=what", # noqa: 501
            text="[]",
        )

        CofenseTriage.get_threat_indicators_command()

        demisto_results = CofenseTriage.demisto.results.call_args_list[0][0]
        assert len(demisto_results) == 1
        assert demisto_results[0]["HumanReadable"] == ("no results were found.")
