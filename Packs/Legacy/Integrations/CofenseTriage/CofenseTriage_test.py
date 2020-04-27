import pytest
from freezegun import freeze_time

from . import CofenseTriage


def fixture_from_file(fname):
    with open(f"test/fixtures/{fname}", "r") as file:
        return file.read()


DEMISTO_ARGS = {}


def set_demisto_arg(name, value):
    DEMISTO_ARGS[name] = value


def get_demisto_arg(name):
    if name in DEMISTO_ARGS:
        return DEMISTO_ARGS[name]
    raise Exception(
        f'Test setup did not specify a Demisto argument named {name}. Use `set_demisto_arg("{name}", "value")`.'
    )


@pytest.fixture(autouse=True)
def stub_demisto_setup(mocker):
    mocker.patch("CofenseTriage.triage_instance.return_error")
    mocker.patch("CofenseTriage.CofenseTriage.fileResult")
    mocker.patch("demistomock.getArg", get_demisto_arg)
    mocker.patch("demistomock.getParam", get_demisto_arg)  # args ≡ params in tests
    mocker.patch("demistomock.results")
    mocker.patch("demistomock.incidents")


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

        CofenseTriage.triage_instance.return_error.assert_called_once()

    @freeze_time("2000-10-31")
    def test_fetch_reports(self, requests_mock):
        set_demisto_arg("max_fetch", 10)
        set_demisto_arg("date_range", "1 day")
        set_demisto_arg("category_id", 5)
        set_demisto_arg("match_priority", 2)
        set_demisto_arg("tags", "")
        requests_mock.get(
            "https://some-triage-host/api/public/v1/processed_reports?category_id=5&match_priority=2&tags=&start_date=2000-10-30T00%3A00%3A00.000000Z",
            text=fixture_from_file("processed_reports.json"),
        )
        requests_mock.get(
            "https://some-triage-host/api/public/v1/reporters/5331",
            text=fixture_from_file("reporters.json"),
        )

        CofenseTriage.fetch_reports()

        demisto_incidents = CofenseTriage.demisto.incidents.call_args_list[0][0][0]
        assert (
            demisto_incidents[0]["name"]
            == "cofense triage report 13363: Phishing Simulation"
        )
        assert demisto_incidents[0]["occurred"] == "2020-03-19T16:43:09.715Z"
        assert demisto_incidents[0]["severity"] == 1

    @freeze_time("2000-10-31")
    def test_search_reports_command(self, requests_mock):
        set_demisto_arg("subject", "suspicious subject")
        set_demisto_arg("url", "")
        set_demisto_arg("file_hash", "")
        set_demisto_arg("reporter", "")
        set_demisto_arg("max_matches", 10)
        set_demisto_arg("verbose", "")
        requests_mock.get(
            "https://some-triage-host/api/public/v1/processed_reports?start_date=2000-10-24T00%3A00%3A00.000000Z",
            text=fixture_from_file("processed_reports.json"),
        )

        CofenseTriage.search_reports_command()

        demisto_results = CofenseTriage.demisto.results.call_args_list[0][0]
        assert len(demisto_results) == 1
        assert demisto_results[0]["HumanReadable"] == (
            "### Reports:\n"
            "|Category Id|Created At|Email Attachments|Id|Location|Match Priority|Md5|Report Body|Report Subject|Reported At|Reporter Id|Sha256|\n"
            "|---|---|---|---|---|---|---|---|---|---|---|---|\n"
            "| 5 | 2020-03-19T16:43:09.715Z | {'id': 18054, 'report_id': 13363, 'decoded_filename': 'image003.png', 'content_type': 'image/png; name=image003.png', 'size_in_bytes': 7286, 'email_attachment_payload': {'id': 7082, 'md5': '123', 'sha256': '1234', 'mime_type': 'image/png; charset=binary'}} | 13363 | Processed | 1 | 111 | From: Sender <sender@example.com><br>Reply-To: \"sender@example.com\" <sender@example.com><br>Date: Wednesday, March 18, 2020 at 3:34 PM<br>To: recipient@example.com<br>Subject: suspicious subject<br>click on this link! trust me! <a href=\"http://example.com/malicious\">here</a> | suspicious subject | 2020-03-19T16:42:22.000Z | 5331 | 222 |\n"
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
            "https://some-triage-host/api/public/v1/processed_reports?start_date=2000-10-24T00%3A00%3A00.000000Z",
            text=fixture_from_file("processed_reports.json"),
        )

        CofenseTriage.search_reports_command()

        demisto_results = CofenseTriage.demisto.results.call_args_list[0][0]
        assert len(demisto_results) == 1
        assert demisto_results[0]["HumanReadable"] == "no results were found."

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
            "| 2019-04-12T02:58:17.401Z | 0 | reporter1@example.com | 111 | 2016-02-18T00:24:45.000Z | 3 | 2019-04-12T02:59:22.287Z | false |\n"
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
            "|Category Id|Created At|Email Attachments|Id|Location|Match Priority|Md5|Report Body|Report Subject|Reported At|Reporter Id|Sha256|\n"
            "|---|---|---|---|---|---|---|---|---|---|---|---|\n"
            "| 7 | 2020-03-19T16:43:09.715Z | {'id': 18054, 'report_id': 13363, 'decoded_filename': 'image003.png', 'content_type': 'image/png; name=image003.png', 'size_in_bytes': 7286, 'email_attachment_payload': {'id': 7082, 'md5': '123', 'sha256': '1234', 'mime_type': 'image/png; charset=binary'}} | 13363 | Processed | 1 | 111 | From: Sender <sender@example.com><br>Reply-To: \"sender@example.com\" <sender@example.com><br>Date: Wednesday, March 18, 2020 at 3:34 PM<br>To: recipient@example.com<br>Subject: suspicious subject<br>click on this link! trust me! <a href=\"http://example.com/malicious\">here</a> | suspicious subject | 2020-03-19T16:42:22.000Z | 5331 | 222 |\n"
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
