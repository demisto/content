from datetime import datetime

import pytest
from freezegun import freeze_time
import datetime

demisto_params = {
    "host": "https://some-triage-host/",
    "token": "api_token",
    "user": "user",
}
with patch("demistomock.params", lambda: demisto_params):
    import CofenseTriage


def fixture_from_file(fname):
    with open(f"test_fixtures/{fname}", "r") as file:
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


def demisto_handle_error(message, error="", outputs=None):
    raise Exception(
        f"Reported error to Demisto: {message} (error={error}) (outputs={outputs})"
    )


@pytest.fixture(autouse=True)
def stub_demisto_setup(mocker):
    mocker.patch("CofenseTriage.return_outputs")
    mocker.patch("CofenseTriage.return_error", demisto_handle_error)
    mocker.patch("CofenseTriage.fileResult")
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

    def test_fetch_reports(self, mocker, requests_mock):
        set_demisto_arg("max_fetch", 10)
        set_demisto_arg("date_range", "unused")
        set_demisto_arg("category_id", 5)
        set_demisto_arg("match_priority", 2)
        set_demisto_arg("tags", "")
        mocker.patch(
            "CofenseTriage.parse_date_range",
            lambda _x, date_format: (
                datetime.fromtimestamp(688867200),
                datetime.fromtimestamp(688867200),
            ),
        )
        requests_mock.get(
            "https://some-triage-host/api/public/v1/processed_reports?category_id=5&match_priority=2&tags=&start_date=1991-10-30+19%3A00%3A00",
            text=fixture_from_file("processed_reports.json"),
        )

        CofenseTriage.fetch_reports()

        CofenseTriage.demisto.incidents.assert_called_with(
            [
                {
                    "name": "cofense triage report 1: Unknown",
                    "occurred": "2000-04-20T01:02:03.000000Z",
                    "rawJSON": '{"id": "1", "subject": "my great subject", "url": "my-great-url", "created_at": "2000-04-20T01:02:03.000000Z", "md5": "md5-value", "sha256": "sha256-value", "reporter_id": "reporter1", "report_body": "report 1 body"}',
                    "severity": 0,
                },
                {
                    "name": "cofense triage report 2: Unknown",
                    "occurred": "2000-04-20T01:02:03.000000Z",
                    "rawJSON": '{"id": "2", "subject": "some other subject that does not match", "url": "my-great-url", "created_at": "2000-04-20T01:02:03.000000Z", "md5": "md5-value", "sha256": "sha256-value", "reporter_id": "reporter2", "report_body": "report 2 body"}',
                    "severity": 0,
                },
                {
                    "name": "cofense triage report 3: Unknown",
                    "occurred": "2000-04-20T01:02:03.000000Z",
                    "rawJSON": '{"id": "3", "subject": "my great subject", "url": "some-url-that-does-not-match", "created_at": "2000-04-20T01:02:03.000000Z", "md5": "md5-value", "sha256": "sha256-value", "reporter_id": "reporter3", "report_body": "report 3 body"}',
                    "severity": 0,
                },
            ]
        )

    def test_search_reports_command(self, mocker, requests_mock):
        set_demisto_arg("subject", "my great subject")
        set_demisto_arg("url", "my-great-url")
        set_demisto_arg("file_hash", "")
        set_demisto_arg("reporter", "")
        set_demisto_arg("max_matches", 10)
        set_demisto_arg("verbose", "")
        mocker.patch(
            "CofenseTriage.parse_date_range",
            lambda _x: (
                datetime.fromtimestamp(688867200),
                datetime.fromtimestamp(688867200),
            ),
        )
        requests_mock.get(
            "https://some-triage-host/api/public/v1/processed_reports?start_date=1991-10-30T19%3A00%3A00.000000Z",
            text=fixture_from_file("processed_reports.json"),
        )

        CofenseTriage.search_reports_command()

        CofenseTriage.demisto.results.assert_called_with(
            {
                "Type": 1,
                "ContentsFormat": "markdown",
                "Contents": [
                    {
                        "created_at": "2000-04-20T01:02:03.000000Z",
                        "id": "1",
                        "md5": "md5-value",
                        "report_body": "report 1 body",
                        "reporter_id": "reporter1",
                        "sha256": "sha256-value",
                    }
                ],
                "HumanReadable": (
                    "### Reports:\n"
                    "|Created At|Id|Md5|Report Body|Reporter Id|Sha256|\n"
                    "|---|---|---|---|---|---|\n"
                    "| 2000-04-20T01:02:03.000000Z | 1 | md5-value | report 1 body | reporter1 | sha256-value |\n"
                ),
                "EntryContext": {
                    "Cofense.Report(val.ID && val.ID == obj.ID)": [
                        {
                            "CreatedAt": "2000-04-20T01:02:03.000000Z",
                            "ID": "1",
                            "Md5": "md5-value",
                            "Sha256": "sha256-value",
                            "ReportBody": "report 1 body",
                            "ReporterId": "reporter1",
                        }
                    ]
                },
            }
        )

    def test_get_attachment_command(self, mocker, requests_mock):
        set_demisto_arg("attachment_id", "5")
        set_demisto_arg("file_name", "my_great_file")
        requests_mock.get(
            "https://some-triage-host/api/public/v1/attachment/5?attachment_id=5",  # TODO get param probably unnecessary
            text=fixture_from_file("attachment.txt"),
        )

        CofenseTriage.get_attachment_command()

        CofenseTriage.fileResult.assert_called_with(
            # TODO use keyword args in the module
            "my_great_file",
            b"A Great Attachment\n",
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

    def test_get_reporter_command(self, mocker, requests_mock):
        set_demisto_arg("reporter_id", "5")
        requests_mock.get(
            "https://some-triage-host/api/public/v1/reporters/5",
            text=fixture_from_file("individual_reporter_response.json"),
        )

        CofenseTriage.get_reporter_command()

        CofenseTriage.return_outputs.assert_called_once_with(
            readable_output="Reporter: user387@cofense.com",
            outputs={
                "Cofense.Reporter(val.ID && val.ID == obj.ID)": {
                    "ID": "5",
                    "Email": "user387@cofense.com",
                }
            },
        )

    def test_get_report_by_id_command(self, requests_mock):
        set_demisto_arg("report_id", "6")
        set_demisto_arg("verbose", "false")
        requests_mock.get(
            "https://some-triage-host/api/public/v1/reports/6?report_id=6",  # TODO that get param is probably unnecessary
            text=fixture_from_file("individual_report_response.json"),
        )
        requests_mock.get(
            "https://some-triage-host/api/public/v1/reporters/5",
            text=fixture_from_file("individual_reporter_response.json"),
        )

        CofenseTriage.get_report_by_id_command()

        CofenseTriage.return_outputs.assert_called_once_with(
            readable_output=(
                "### Report Summary:\n"
                "|Cluster Id|Id|Reporter|Reporter Id|\n"
                "|---|---|---|---|\n"
                "| 212 | 6 | user387@cofense.com | 5 |\n"
            ),
            outputs={
                "Cofense.Report(val.ID && val.ID == obj.ID)": [
                    {
                        "ClusterId": "212",
                        "ID": "6",
                        "Reporter": "user387@cofense.com",
                        "ReporterId": "5",
                    }
                ]
            },
        )

    def test_get_all_reporters(self, requests_mock):
        requests_mock.get(
            "https://some-triage-host/api/public/v1/reporters?start_date=1995-01-01",
            text=fixture_from_file("reporters_response.json"),
        )

        reporters = CofenseTriage.get_all_reporters("1995-01-01")

        assert reporters == [
            "user1@cofense.com",
            "user2@cofense.com",
            "user3@cofense.com",
        ]

    def test_malformed_json(self, mocker, requests_mock):
        mocker.patch(
            "CofenseTriage.return_error"
        )  # we expect an error, so stub out the re-raising behavior
        requests_mock.get(
            "https://some-triage-host/api/public/v1/processed_reports",
            text=fixture_from_file("malformed_json.json"),
        )

        CofenseTriage.http_request("/processed_reports")

        CofenseTriage.return_error.assert_called_with(
            "Error in API call to Cofense Triage, could not parse result [200]"
        )

    def test_error_from_triage(self, mocker, requests_mock):
        mocker.patch(
            "CofenseTriage.return_error"
        )  # we expect an error, so stub out the re-raising behavior
        requests_mock.get(
            "https://some-triage-host/api/public/v1/processed_reports",
            text='{"message": "some error message"}',
            status_code=403,
        )

        CofenseTriage.http_request("/processed_reports")

        CofenseTriage.return_error.assert_called_with(
            'Call to Cofense Triage failed [403] - [{"message": "some error message"}]'
        )
