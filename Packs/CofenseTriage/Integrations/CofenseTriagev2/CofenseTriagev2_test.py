import datetime
from pathlib import Path
from unittest.mock import patch

import pytest
from CofenseTriagev2 import TriageInboxReports
from CofenseTriagev2 import TriageReport
from CofenseTriagev2 import TriageReporter
from CofenseTriagev2 import TriageRequestFailedError
from CofenseTriagev2 import TriageNoReportersFoundError
from freezegun import freeze_time


@pytest.fixture
def fixture_from_file():
    def _fixture_from_file(fname):
        with (Path(__file__).parent / 'test_data' / 'fixtures' / fname).open() as file:
            return file.read()
    return _fixture_from_file


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
set_demisto_arg("date_range", "1 day")
set_demisto_arg("max_fetch", 30)
set_demisto_arg("category_id", "")
set_demisto_arg("match_priority", "")
set_demisto_arg("tags", "")
set_demisto_arg("mailbox_location", "Processed_Reports")
patch("demistomock.getParam", get_demisto_arg)  # args ≡ params in tests

import CofenseTriagev2  # noqa: E402
from CofenseTriagev2 import parse_triage_date  # noqa: E402


@pytest.fixture(autouse=True)
def stub_demisto_setup(mocker):
    mocker.patch("CofenseTriagev2.return_error")
    mocker.patch(
        "CofenseTriagev2.fileResult",
        lambda filename="file_result_name", data="file_result_id": {
            "Contents": "",
            "ContentsFormat": "text",
            "Type": "what",
            "File": filename,
            "FileID": "/path/to/temp/file",
        },
    )
    mocker.patch("demistomock.getArg", get_demisto_arg)
    mocker.patch("demistomock.getParam", get_demisto_arg)  # args ≡ params in tests
    mocker.patch("demistomock.results")
    mocker.patch("demistomock.incidents")
    mocker.patch("demistomock.setLastRun")


@pytest.fixture
@freeze_time("2000-10-31")
def triage_instance():
    return CofenseTriagev2.build_triage_instance()


class TestCofenseTriage:
    def test_test_function(self, requests_mock, triage_instance, fixture_from_file):
        requests_mock.get(
            "https://some-triage-host/api/public/v1/processed_reports",
            text=fixture_from_file("processed_reports.json"),
        )

        CofenseTriagev2.test_function(triage_instance)

        CofenseTriagev2.demisto.results.assert_called_once_with("ok")

    def test_test_function_error(self, requests_mock, triage_instance, fixture_from_file):
        requests_mock.get(
            "https://some-triage-host/api/public/v1/processed_reports",
            status_code=404,
            text=fixture_from_file("processed_reports.json"),
        )

        with pytest.raises(TriageRequestFailedError):
            CofenseTriagev2.test_function(triage_instance)

    @freeze_time("2000-10-31")
    def test_fetch_reports(self, mocker, requests_mock, triage_instance, fixture_from_file):
        requests_mock.get(
            "https://some-triage-host/api/public/v1/processed_reports?category_id=&"
            "match_priority=&tags=&start_date=2000-10-30T00%3A00%3A00",
            # noqa: E501
            text=fixture_from_file("processed_reports.json"),
        )
        requests_mock.get(
            "https://some-triage-host/api/public/v1/reporters/5331",
            text=fixture_from_file("reporters.json"),
        )

        CofenseTriagev2.fetch_reports(triage_instance)

        demisto_incidents = CofenseTriagev2.demisto.incidents.call_args_list[0][0][0]
        assert len(demisto_incidents) == 2
        assert demisto_incidents[0]["name"] == "cofense triage report 13363: Phishing Simulation"
        assert demisto_incidents[0]["occurred"] == "2020-03-19T16:43:09.715Z"
        assert demisto_incidents[0]["severity"] == 1
        assert len(demisto_incidents[0]["rawJSON"]) == 1931

        assert demisto_incidents[1]["attachment"] == [
            {"name": "13392-report.html", "path": "/path/to/temp/file"}
        ]

        CofenseTriagev2.demisto.setLastRun.assert_called_once_with(
            {"reports_fetched": "[13392, 13363]"}
        )

    @freeze_time("2000-10-31")
    def test_fetch_reports_already_fetched(
            self, mocker, requests_mock, triage_instance, fixture_from_file
    ):
        requests_mock.get(
            "https://some-triage-host/api/public/v1/processed_reports?category_id=&"
            "match_priority=&tags=&start_date=2000-10-30T00%3A00%3A00",
            # noqa: E501
            text=fixture_from_file("processed_reports.json"),
        )
        requests_mock.get(
            "https://some-triage-host/api/public/v1/reporters/5331",
            text=fixture_from_file("reporters.json"),
        )
        mocker.patch("demistomock.getLastRun", lambda: {"reports_fetched": "[13363]"})

        CofenseTriagev2.fetch_reports(triage_instance)

        demisto_incidents = CofenseTriagev2.demisto.incidents.call_args_list[0][0][0]
        assert len(demisto_incidents) == 1
        assert demisto_incidents[0]["name"] == "cofense triage report 13392: Crimeware"

        CofenseTriagev2.demisto.setLastRun.assert_called_once_with(
            {"reports_fetched": "[13392, 13363]"}
        )

    @freeze_time("2000-10-31")
    def test_search_reports_command(self, requests_mock, triage_instance, fixture_from_file):
        set_demisto_arg("subject", "suspicious subject")
        set_demisto_arg("url", "")
        set_demisto_arg("file_hash", "")
        set_demisto_arg("reporter", "")
        set_demisto_arg("max_matches", 10)
        set_demisto_arg("verbose", "")
        requests_mock.get(
            "https://some-triage-host/api/public/v1/processed_reports?start_date=2000-10-24+00%3A00%3A00%2B00%3A00",
            # noqa: E501
            text=fixture_from_file("processed_reports.json"),
        )

        CofenseTriagev2.search_reports_command(triage_instance)

        demisto_results = CofenseTriagev2.demisto.results.call_args_list[0][0]
        assert len(demisto_results) == 1
        assert demisto_results[0]["HumanReadable"] == (
            "### Reports:\n"
            "|Category Id|Created At|Email Attachments|Id|Location|Match Priority|Md5|Report Body|Report Subject|Reported At|Reporter Id|Sha256|\n"  # noqa: E501
            "|---|---|---|---|---|---|---|---|---|---|---|---|\n"  # noqa: E501
            "| 5 | 2020-03-19T16:43:09.715Z | {'id': 18054, 'report_id': 13363, 'decoded_filename': 'image003.png', 'content_type': 'image/png; name=image003.png', 'size_in_bytes': 7286, 'email_attachment_payload': {'id': 7082, 'md5': '123', 'sha256': '1234', 'mime_type': 'image/png; charset=binary'}} | 13363 | Processed | 1 | 111 | From: Sender <sender@example.com><br>Reply-To: \"sender@example.com\" <sender@example.com><br>Date: Wednesday, March 18, 2020 at 3:34 PM<br>To: recipient@example.com<br>Subject: suspicious subject<br>click on this link! trust me! <a href=\"http://example.com/malicious\">here</a> | suspicious subject | 2020-03-19T16:42:22.000Z | 5331 | 222 |\n"  # noqa: E501
        )

    def test_build_reporters_clause_found(self, requests_mock, triage_instance, fixture_from_file):
        set_demisto_arg("reporter", "reporter2@example.com")

        requests_mock.get(
            "https://some-triage-host/api/public/v1/reporters?email=reporter2%40example.com&page=0",  # noqa: E501
            text=fixture_from_file("reporters_by_email_reporter2.json"),
        )
        requests_mock.get(
            "https://some-triage-host/api/public/v1/reporters/222",
            text=fixture_from_file("reporters.json"),
        )

        assert CofenseTriagev2.build_reporters_clause(triage_instance) == {"reporter_ids": [111]}

    def test_build_reporters_clause_id(self, requests_mock, triage_instance, fixture_from_file):
        set_demisto_arg("reporter", "222")

        requests_mock.get(
            "https://some-triage-host/api/public/v1/reporters/222",
            text=fixture_from_file("reporters.json"),
        )

        assert CofenseTriagev2.build_reporters_clause(triage_instance) == {"reporter_ids": [222]}

    def test_build_reporters_clause_not_found(self, requests_mock, triage_instance):
        set_demisto_arg("reporter", "does_not_exist@example.com")

        requests_mock.get(
            "https://some-triage-host/api/public/v1/reporters?email=does_not_exist%40example.com&page=0",  # noqa: E501
            text="[]",
        )

        with pytest.raises(TriageNoReportersFoundError):
            CofenseTriagev2.build_reporters_clause(triage_instance)

    def test_build_reporters_clause_nothing_specified(self, requests_mock, triage_instance):
        set_demisto_arg("reporter", "")

        assert CofenseTriagev2.build_reporters_clause(triage_instance) == {}

    @freeze_time("2000-10-31")
    def test_search_reports_command_not_found(self, requests_mock, triage_instance, fixture_from_file):
        set_demisto_arg("subject", "my great subject")
        set_demisto_arg("url", "my-great-url")
        set_demisto_arg("file_hash", "")
        set_demisto_arg("reporter", "")
        set_demisto_arg("max_matches", 10)
        set_demisto_arg("verbose", "")
        requests_mock.get(
            "https://some-triage-host/api/public/v1/processed_reports?start_date=2000-10-24+00%3A00%3A00%2B00%3A00",
            text=fixture_from_file("processed_reports.json"),
        )

        CofenseTriagev2.search_reports_command(triage_instance)

        demisto_results = CofenseTriagev2.demisto.results.call_args_list[0][0]
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
            ({"created_at": parse_triage_date("1999-03-19T16:43:09.715Z")}, [13363, 13392],),
            ({"file_hash": "123"}, [13363]),
            ({"file_hash": "1234"}, [13363]),
            ({"file_hash": "5"}, []),
        ],
    )
    def test_search_reports_filtering(
            self, requests_mock, triage_instance, filter_attrs, expected_found_report_ids, fixture_from_file
    ):
        requests_mock.get(
            "https://some-triage-host/api/public/v1/processed_reports?start_date=2000-10-31+00%3A00%3A00",  # noqa: E501
            text=fixture_from_file("processed_reports.json"),
        )

        found_reports = CofenseTriagev2.search_reports(
            triage_instance, **filter_attrs, reported_at=datetime.datetime.now()
        )
        assert [report["id"] for report in found_reports] == expected_found_report_ids

    @freeze_time("2000-10-31")
    def test_search_inbox_reports_command(self, requests_mock, triage_instance, fixture_from_file):
        set_demisto_arg("subject", "aaa")
        set_demisto_arg("url", "")
        set_demisto_arg("file_hash", "")
        set_demisto_arg("reporter", "")
        set_demisto_arg("max_matches", 10)
        requests_mock.get(
            "https://some-triage-host/api/public/v1/inbox_reports?start_date=2000-10-24+00%3A00%3A00%2B00%3A00&page=0",  # noqa: E501
            text=fixture_from_file("inbox_reports.json"),
        )
        requests_mock.get(
            "https://some-triage-host/api/public/v1/reporters/222",
            text=fixture_from_file("reporters.json"),
        )

        CofenseTriagev2.search_inbox_reports_command(triage_instance)

        demisto_results = CofenseTriagev2.demisto.results.call_args_list[0][0]
        assert len(demisto_results) == 1
        assert demisto_results[0]["HumanReadable"] == (
            "### Reports:\n"
            "|Cluster Id|Created At|Email Attachments|Email Urls|Id|Location|Match Priority|Md5|Report Body|Report Headers|Report Subject|Reported At|Reporter Created At|Reporter Credibility Score|Reporter Email|Reporter Id|Reporter Last Reported At|Reporter Phishme Reports Count|Reporter Reports Count|Reporter Updated At|Reporter Vip|Rules|Sha256|Suspect Received At|Updated At|\n"  # noqa: E501
            "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n"
            "| 3887 | 2020-08-26T15:13:30.920Z | {'id': 18054, 'report_id': 13363, 'decoded_filename': 'image003.png', 'content_type': 'image/png; name=image003.png', 'size_in_bytes': 7286, 'email_attachment_payload': {'id': 7082, 'md5': '123', 'sha256': '1234', 'mime_type': 'image/png; charset=binary'}} | {'url': 'https://example.com/url1.png'},<br>{'url': 'https://example.com/url2.png'},<br>{'url': 'https://example.com/url3.png'} | 13461 | Inbox | 1 | 555 | Report body 1 | Date: Wed, 26 Aug 2020 15:13:30 +0000<br>Subject: Report subject 1<br>Mime-Version: 1.0<br>Content-Type: multipart/mixed;<br>charset=UTF-8<br>Content-Transfer-Encoding: 7bit | Report subject 1 aaa | 2020-08-26T14:36:43.000Z | 2019-04-12T02:58:17.401Z | 0 | reporter1@example.com | 111 | 2016-02-18T00:24:45.000Z | 0 | 3 | 2019-04-12T02:59:22.287Z | false | {'id': 6417, 'name': 'Triage_rule_1', 'reports_count': 67, 'active': True, 'created_at': '2019-04-11T17:15:53.940Z', 'updated_at': '2019-04-11T17:15:53.940Z', 'priority': 1, 'author_name': 'Cofense'} | 555555 | 2020-08-26T14:36:51.000Z | 2020-08-26T15:13:35.200Z |\n"  # noqa: E501
            "| 3884 | 2020-08-24T16:43:04.412Z |  | {'url': 'https://example.com/url1.png'},<br>{'url': 'https://example.com/url2.png'},<br>{'url': 'https://example.com/url3.png'} | 13458 | Inbox | 1 | 555 | Report body 3 | Date: Wed, 26 Aug 2020 15:13:30 +0000<br>Subject: Report subject 3<br>Mime-Version: 1.0<br>Content-Type: multipart/mixed;<br>charset=UTF-8<br>Content-Transfer-Encoding: 7bit | Report subject 3 aaa | 2020-08-24T16:15:52.000Z | 2019-04-12T02:58:17.401Z | 0 | reporter1@example.com | 111 | 2016-02-18T00:24:45.000Z | 0 | 3 | 2019-04-12T02:59:22.287Z | false | {'id': 667, 'name': 'Triage_rule_1', 'reports_count': 41, 'active': True, 'created_at': '2019-04-11T16:46:11.078Z', 'updated_at': '2019-04-11T16:46:11.078Z', 'priority': 1, 'author_name': 'Cofense'} | 555555 | 2020-08-24T16:21:07.000Z | 2020-08-24T16:43:05.946Z |\n"  # noqa: E501
        )

    @freeze_time("2000-10-31")
    def test_search_inbox_reports_command_with_reporter(self, requests_mock, triage_instance, fixture_from_file):
        set_demisto_arg("subject", "aaa")
        set_demisto_arg("url", "")
        set_demisto_arg("file_hash", "")
        set_demisto_arg("reporter", "reporter2")
        set_demisto_arg("max_matches", 10)
        requests_mock.get(
            "https://some-triage-host/api/public/v1/inbox_reports?start_date=2000-10-24+00%3A00%3A00%2B00%3A00&page=0",  # noqa: E501
            text=fixture_from_file("inbox_reports.json"),
        )
        requests_mock.get(
            "https://some-triage-host/api/public/v1/reporters?email=reporter2&page=0",
            text=fixture_from_file("reporters_by_email_reporter2.json"),
        )
        requests_mock.get(
            "https://some-triage-host/api/public/v1/reporters/222",
            text=fixture_from_file("reporters.json"),
        )

        CofenseTriagev2.search_inbox_reports_command(triage_instance)

        demisto_results = CofenseTriagev2.demisto.results.call_args_list[0][0]
        assert len(demisto_results) == 1
        assert demisto_results[0]["HumanReadable"] == (
            "### Reports:\n"
            "|Cluster Id|Created At|Email Attachments|Email Urls|Id|Location|Match Priority|Md5|Report Body|Report Headers|Report Subject|Reported At|Reporter Created At|Reporter Credibility Score|Reporter Email|Reporter Id|Reporter Last Reported At|Reporter Phishme Reports Count|Reporter Reports Count|Reporter Updated At|Reporter Vip|Rules|Sha256|Suspect Received At|Updated At|\n"  # noqa: E501
            "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n"
            "| 3887 | 2020-08-26T15:13:30.920Z | {'id': 18054, 'report_id': 13363, 'decoded_filename': 'image003.png', 'content_type': 'image/png; name=image003.png', 'size_in_bytes': 7286, 'email_attachment_payload': {'id': 7082, 'md5': '123', 'sha256': '1234', 'mime_type': 'image/png; charset=binary'}} | {'url': 'https://example.com/url1.png'},<br>{'url': 'https://example.com/url2.png'},<br>{'url': 'https://example.com/url3.png'} | 13461 | Inbox | 1 | 555 | Report body 1 | Date: Wed, 26 Aug 2020 15:13:30 +0000<br>Subject: Report subject 1<br>Mime-Version: 1.0<br>Content-Type: multipart/mixed;<br>charset=UTF-8<br>Content-Transfer-Encoding: 7bit | Report subject 1 aaa | 2020-08-26T14:36:43.000Z | 2019-04-12T02:58:17.401Z | 0 | reporter1@example.com | 111 | 2016-02-18T00:24:45.000Z | 0 | 3 | 2019-04-12T02:59:22.287Z | false | {'id': 6417, 'name': 'Triage_rule_1', 'reports_count': 67, 'active': True, 'created_at': '2019-04-11T17:15:53.940Z', 'updated_at': '2019-04-11T17:15:53.940Z', 'priority': 1, 'author_name': 'Cofense'} | 555555 | 2020-08-26T14:36:51.000Z | 2020-08-26T15:13:35.200Z |\n"  # noqa: E501
            "| 3884 | 2020-08-24T16:43:04.412Z |  | {'url': 'https://example.com/url1.png'},<br>{'url': 'https://example.com/url2.png'},<br>{'url': 'https://example.com/url3.png'} | 13458 | Inbox | 1 | 555 | Report body 3 | Date: Wed, 26 Aug 2020 15:13:30 +0000<br>Subject: Report subject 3<br>Mime-Version: 1.0<br>Content-Type: multipart/mixed;<br>charset=UTF-8<br>Content-Transfer-Encoding: 7bit | Report subject 3 aaa | 2020-08-24T16:15:52.000Z | 2019-04-12T02:58:17.401Z | 0 | reporter1@example.com | 111 | 2016-02-18T00:24:45.000Z | 0 | 3 | 2019-04-12T02:59:22.287Z | false | {'id': 667, 'name': 'Triage_rule_1', 'reports_count': 41, 'active': True, 'created_at': '2019-04-11T16:46:11.078Z', 'updated_at': '2019-04-11T16:46:11.078Z', 'priority': 1, 'author_name': 'Cofense'} | 555555 | 2020-08-24T16:21:07.000Z | 2020-08-24T16:43:05.946Z |\n"  # noqa: E501
        )

    @freeze_time("2000-10-31")
    def test_search_inbox_reports_command_with_file_hash(self, requests_mock, triage_instance, fixture_from_file):
        set_demisto_arg("subject", "aaa")
        set_demisto_arg("url", "")
        set_demisto_arg("file_hash", "1234")
        set_demisto_arg("reporter", "")
        set_demisto_arg("max_matches", 10)
        requests_mock.get(
            "https://some-triage-host/api/public/v1/inbox_reports?start_date=2000-10-24+00%3A00%3A00%2B00%3A00&page=0",  # noqa: E501
            text=fixture_from_file("inbox_reports.json"),
        )
        requests_mock.get(
            "https://some-triage-host/api/public/v1/reporters/222",
            text=fixture_from_file("reporters.json"),
        )

        CofenseTriagev2.search_inbox_reports_command(triage_instance)

        demisto_results = CofenseTriagev2.demisto.results.call_args_list[0][0]
        assert len(demisto_results) == 1
        assert demisto_results[0]["HumanReadable"] == (
            "### Reports:\n"
            "|Cluster Id|Created At|Email Attachments|Email Urls|Id|Location|Match Priority|Md5|Report Body|Report Headers|Report Subject|Reported At|Reporter Created At|Reporter Credibility Score|Reporter Email|Reporter Id|Reporter Last Reported At|Reporter Phishme Reports Count|Reporter Reports Count|Reporter Updated At|Reporter Vip|Rules|Sha256|Suspect Received At|Updated At|\n"  # noqa: E501
            "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n"
            "| 3887 | 2020-08-26T15:13:30.920Z | {'id': 18054, 'report_id': 13363, 'decoded_filename': 'image003.png', 'content_type': 'image/png; name=image003.png', 'size_in_bytes': 7286, 'email_attachment_payload': {'id': 7082, 'md5': '123', 'sha256': '1234', 'mime_type': 'image/png; charset=binary'}} | {'url': 'https://example.com/url1.png'},<br>{'url': 'https://example.com/url2.png'},<br>{'url': 'https://example.com/url3.png'} | 13461 | Inbox | 1 | 555 | Report body 1 | Date: Wed, 26 Aug 2020 15:13:30 +0000<br>Subject: Report subject 1<br>Mime-Version: 1.0<br>Content-Type: multipart/mixed;<br>charset=UTF-8<br>Content-Transfer-Encoding: 7bit | Report subject 1 aaa | 2020-08-26T14:36:43.000Z | 2019-04-12T02:58:17.401Z | 0 | reporter1@example.com | 111 | 2016-02-18T00:24:45.000Z | 0 | 3 | 2019-04-12T02:59:22.287Z | false | {'id': 6417, 'name': 'Triage_rule_1', 'reports_count': 67, 'active': True, 'created_at': '2019-04-11T17:15:53.940Z', 'updated_at': '2019-04-11T17:15:53.940Z', 'priority': 1, 'author_name': 'Cofense'} | 555555 | 2020-08-26T14:36:51.000Z | 2020-08-26T15:13:35.200Z |\n"  # noqa: E501
        )

    @freeze_time("2000-10-31")
    def test_search_inbox_reports_command_with_max_matches(self, requests_mock, triage_instance, fixture_from_file):
        set_demisto_arg("subject", "aaa")
        set_demisto_arg("url", "")
        set_demisto_arg("file_hash", "")
        set_demisto_arg("reporter", "reporter2")
        set_demisto_arg("max_matches", 1)
        requests_mock.get(
            "https://some-triage-host/api/public/v1/inbox_reports?start_date=2000-10-24+00%3A00%3A00%2B00%3A00&page=0",  # noqa: E501
            text=fixture_from_file("inbox_reports.json"),
        )
        requests_mock.get(
            "https://some-triage-host/api/public/v1/reporters?email=reporter2&page=0",
            text=fixture_from_file("reporters_by_email_reporter2.json"),
        )
        requests_mock.get(
            "https://some-triage-host/api/public/v1/reporters/222",
            text=fixture_from_file("reporters.json"),
        )

        CofenseTriagev2.search_inbox_reports_command(triage_instance)

        demisto_results = CofenseTriagev2.demisto.results.call_args_list[0][0]
        assert len(demisto_results) == 1
        assert demisto_results[0]["HumanReadable"] == (
            "### Reports:\n"
            "|Cluster Id|Created At|Email Attachments|Email Urls|Id|Location|Match Priority|Md5|Report Body|Report Headers|Report Subject|Reported At|Reporter Created At|Reporter Credibility Score|Reporter Email|Reporter Id|Reporter Last Reported At|Reporter Phishme Reports Count|Reporter Reports Count|Reporter Updated At|Reporter Vip|Rules|Sha256|Suspect Received At|Updated At|\n"  # noqa: E501
            "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n"
            "| 3887 | 2020-08-26T15:13:30.920Z | {'id': 18054, 'report_id': 13363, 'decoded_filename': 'image003.png', 'content_type': 'image/png; name=image003.png', 'size_in_bytes': 7286, 'email_attachment_payload': {'id': 7082, 'md5': '123', 'sha256': '1234', 'mime_type': 'image/png; charset=binary'}} | {'url': 'https://example.com/url1.png'},<br>{'url': 'https://example.com/url2.png'},<br>{'url': 'https://example.com/url3.png'} | 13461 | Inbox | 1 | 555 | Report body 1 | Date: Wed, 26 Aug 2020 15:13:30 +0000<br>Subject: Report subject 1<br>Mime-Version: 1.0<br>Content-Type: multipart/mixed;<br>charset=UTF-8<br>Content-Transfer-Encoding: 7bit | Report subject 1 aaa | 2020-08-26T14:36:43.000Z | 2019-04-12T02:58:17.401Z | 0 | reporter1@example.com | 111 | 2016-02-18T00:24:45.000Z | 0 | 3 | 2019-04-12T02:59:22.287Z | false | {'id': 6417, 'name': 'Triage_rule_1', 'reports_count': 67, 'active': True, 'created_at': '2019-04-11T17:15:53.940Z', 'updated_at': '2019-04-11T17:15:53.940Z', 'priority': 1, 'author_name': 'Cofense'} | 555555 | 2020-08-26T14:36:51.000Z | 2020-08-26T15:13:35.200Z |\n"  # noqa: E501
        )

    def test_get_attachment_command(self, mocker, requests_mock, triage_instance, fixture_from_file):
        set_demisto_arg("attachment_id", "5")
        set_demisto_arg("file_name", "my_great_file")
        requests_mock.get(
            "https://some-triage-host/api/public/v1/attachment/5",
            text=fixture_from_file("attachment.txt"),
        )

        CofenseTriagev2.get_attachment_command(triage_instance)

        CofenseTriagev2.get_attachment_command(triage_instance)

        demisto_results = CofenseTriagev2.demisto.results.call_args_list[0][0]
        assert demisto_results[0]["FileID"] == "/path/to/temp/file"
        assert demisto_results[0]["File"] == "my_great_file"

    def test_get_reporter_command(self, requests_mock, triage_instance, fixture_from_file):
        set_demisto_arg("reporter_id", "5")
        requests_mock.get(
            "https://some-triage-host/api/public/v1/reporters/5",
            text=fixture_from_file("reporters.json"),
        )

        CofenseTriagev2.get_reporter_command(triage_instance)

        demisto_results = CofenseTriagev2.demisto.results.call_args_list[0][0]
        assert demisto_results[0]["HumanReadable"] == (
            "### Reporter Results:\n"
            "|Created At|Credibility Score|Email|Id|Last Reported At|Reports Count|Updated At|Vip|\n"
            "|---|---|---|---|---|---|---|---|\n"
            "| 2019-04-12T02:58:17.401Z | 0 | reporter1@example.com | 111 | 2016-02-18T00:24:45.000Z | 3 | 2019-04-12T02:59:22.287Z | false |\n"  # noqa: E501
        )
        assert demisto_results[0]["EntryContext"] == {
            "Cofense.Reporter(val.Id && val.Id == obj.Id)": {
                "ID": 111,
                "Email": "reporter1@example.com",
                "CreatedAt": "2019-04-12T02:58:17.401Z",
                "UpdatedAt": "2019-04-12T02:59:22.287Z",
                "CredibilityScore": 0,
                "ReportsCount": 3,
                "LastReportedAt": "2016-02-18T00:24:45.000Z",
                "Vip": False,
            }
        }

    def test_get_report_by_id_command(self, requests_mock, triage_instance, fixture_from_file):
        set_demisto_arg("report_id", "6")
        set_demisto_arg("verbose", "false")
        requests_mock.get(
            "https://some-triage-host/api/public/v1/reports/6",
            text=fixture_from_file("single_report.json"),
        )
        requests_mock.get(
            "https://some-triage-host/api/public/v1/reporters/5331",
            text=fixture_from_file("reporters.json"),
        )

        CofenseTriagev2.get_report_by_id_command(triage_instance)

        demisto_results = CofenseTriagev2.demisto.results.call_args_list[0][0]
        assert demisto_results[0]["HumanReadable"] == (
            "### Report Summary:\n"
            "|Category Id|Created At|Email Attachments|Id|Location|Match Priority|Md5|Report Body|Report Subject|Reported At|Reporter Id|Sha256|\n"  # noqa: E501
            "|---|---|---|---|---|---|---|---|---|---|---|---|\n"
            "| 7 | 2020-03-19T16:43:09.715Z | {'id': 18054, 'report_id': 13363, 'decoded_filename': 'image003.png', 'content_type': 'image/png; name=image003.png', 'size_in_bytes': 7286, 'email_attachment_payload': {'id': 7082, 'md5': '123', 'sha256': '1234', 'mime_type': 'image/png; charset=binary'}} | 13363 | Processed | 1 | 111 | From: Sender <sender@example.com><br>Reply-To: \"sender@example.com\" <sender@example.com><br>Date: Wednesday, March 18, 2020 at 3:34 PM<br>To: recipient@example.com<br>Subject: suspicious subject<br>click on this link! trust me! <a href=\"http://example.com/malicious\">here</a> | suspicious subject | 2020-03-19T16:42:22.000Z | 5331 | 222 |\n"  # noqa: E501
        )

    def test_get_report_by_id_command_with_attachment(
            self, requests_mock, triage_instance, fixture_from_file
    ):
        set_demisto_arg("report_id", "6")
        set_demisto_arg("verbose", "false")
        requests_mock.get(
            "https://some-triage-host/api/public/v1/reports/6",
            text=fixture_from_file("single_report_with_attachment.json"),
        )
        requests_mock.get(
            "https://some-triage-host/api/public/v1/reporters/5331",
            text=fixture_from_file("reporters.json"),
        )

        CofenseTriagev2.get_report_by_id_command(triage_instance)

        demisto_results = CofenseTriagev2.demisto.results.call_args_list
        assert demisto_results[0][0][0]["HumanReadable"] == (
            "### Cofense HTML Report:\n"
            "HTML report download request has been completed"
        )
        assert demisto_results[1][0][0]["HumanReadable"] == (
            "### Report Summary:\n"
            "|Category Id|Created At|Email Attachments|Id|Location|Match Priority|Md5|Report Subject|Reported At|Reporter Id|Sha256|\n"  # noqa: E501
            "|---|---|---|---|---|---|---|---|---|---|---|\n"
            "| 7 | 2020-03-19T16:43:09.715Z | {'id': 18054, 'report_id': 13363, 'decoded_filename': 'image003.png', 'content_type': 'image/png; name=image003.png', 'size_in_bytes': 7286, 'email_attachment_payload': {'id': 7082, 'md5': '123', 'sha256': '1234', 'mime_type': 'image/png; charset=binary'}} | 13363 | Processed | 1 | 111 | suspicious subject | 2020-03-19T16:42:22.000Z | 5331 | 222 |\n"  # noqa: E501
        )

    def test_get_all_reporters(self, requests_mock, triage_instance, fixture_from_file):
        requests_mock.get(
            "https://some-triage-host/api/public/v1/reporters?start_date=1995-01-01",
            text=fixture_from_file("reporters.json"),
        )

        reporters = CofenseTriagev2.get_all_reporters(triage_instance, "1995-01-01")

        assert reporters == [
            "reporter1@example.com",
            "reporter2@example.com",
        ]

    def test_get_threat_indicators_command(self, requests_mock, triage_instance, fixture_from_file):
        set_demisto_arg("type", "what")
        set_demisto_arg("level", "what")
        set_demisto_arg("start_date", "what")
        set_demisto_arg("end_date", "what")
        set_demisto_arg("page", "what")
        set_demisto_arg("per_page", "what")
        requests_mock.get(
            "https://some-triage-host/api/public/v1/triage_threat_indicators?type=what&level=what&start_date=what&end_date=what&page=what&per_page=what",  # noqa: E501
            text=fixture_from_file("threat_indicators.json"),
        )

        CofenseTriagev2.get_threat_indicators_command(triage_instance)

        demisto_results = CofenseTriagev2.demisto.results.call_args_list[0][0]
        assert len(demisto_results) == 1
        assert demisto_results[0]["HumanReadable"] == (
            "### Threat Indicators:\n"
            "|Created At|Id|Operator Id|Report Id|Threat Key|Threat Level|Threat Value|\n"
            "|---|---|---|---|---|---|---|\n"
            "| 2020-03-16T17:39:14.579Z | 37 | 2 | 13353 | Domain | Malicious | malicious.example.com |\n"
        )

    def test_get_threat_indicators_command_not_found(
            self, requests_mock, triage_instance
    ):
        set_demisto_arg("type", "what")
        set_demisto_arg("level", "what")
        set_demisto_arg("start_date", "what")
        set_demisto_arg("end_date", "what")
        set_demisto_arg("page", "what")
        set_demisto_arg("per_page", "what")
        requests_mock.get(
            "https://some-triage-host/api/public/v1/triage_threat_indicators?type=what&level=what&start_date=what&end_date=what&page=what&per_page=what",  # noqa: E501
            text="[]",
        )

        CofenseTriagev2.get_threat_indicators_command(triage_instance)

        demisto_results = CofenseTriagev2.demisto.results.call_args_list[0][0]
        assert len(demisto_results) == 1
        assert demisto_results[0]["HumanReadable"] == ("no results were found.")


class TestTriageInstance:
    def test_request(self, requests_mock, triage_instance, fixture_from_file):
        requests_mock.get(
            "https://some-triage-host/api/public/v1/processed_reports",
            text=fixture_from_file("processed_reports.json"),
        )

        requests = triage_instance.request("processed_reports")

        assert len(requests) == 2
        assert requests[0]["report_subject"] == "suspicious subject"

    def test_request_unsuccessful(self, mocker, requests_mock, triage_instance):
        requests_mock.get(
            "https://some-triage-host/api/public/v1/processed_reports",
            status_code=403,
            text="a bad error",
        )

        with pytest.raises(TriageRequestFailedError) as e:
            triage_instance.request("processed_reports")

            assert e.message == "Call to Cofense Triage failed (403): a bad error"

    def test_request_raw(self, requests_mock, triage_instance, fixture_from_file):
        requests_mock.get(
            "https://some-triage-host/api/public/v1/processed_reports",
            text=fixture_from_file("processed_reports.json"),
        )

        response = triage_instance.request("processed_reports", raw_response=True)

        assert response.__class__.__name__ == "Response"

    def test_request_empty(self, requests_mock, triage_instance):
        requests_mock.get(
            "https://some-triage-host/api/public/v1/processed_reports", text="[]"
        )

        assert triage_instance.request("processed_reports") == {}

    def test_request_malformed_json(
            self, mocker, requests_mock, triage_instance, fixture_from_file
    ):
        requests_mock.get(
            "https://some-triage-host/api/public/v1/processed_reports",
            text=fixture_from_file("malformed_json.not_json"),
        )

        with pytest.raises(TriageRequestFailedError) as e:
            triage_instance.request("processed_reports")

            assert e.message == "Could not parse result from Cofense Triage (200)"

    def test_api_url(self, triage_instance):
        assert triage_instance.api_url("endpoint") == "https://some-triage-host/api/public/v1/endpoint"
        assert triage_instance.api_url("/endpoint") == "https://some-triage-host/api/public/v1/endpoint"
        assert triage_instance.api_url("///endpoint/edit?query_string&") == "https://some-triage-host/api/public/v1/endpoint/edit?query_string&"  # noqa 501


class TestTriageInboxReports:
    def test_inbox_reports(self, requests_mock, triage_instance, fixture_from_file):
        requests_mock.get(
            "https://some-triage-host/api/public/v1/inbox_reports?page=0",
            text=fixture_from_file("inbox_reports.json"),
        )

        reports = TriageInboxReports(triage_instance).inbox_reports()

        assert len(reports) == 3
        assert reports[0].id == 13461
        assert reports[2].date == "2020-08-24T16:43:04.412Z"

    def test_inbox_reports_with_filter(
        self, requests_mock, triage_instance, fixture_from_file
    ):
        requests_mock.get(
            "https://some-triage-host/api/public/v1/inbox_reports?page=0",
            text=fixture_from_file("inbox_reports.json"),
        )

        reports = TriageInboxReports(
            triage_instance, filter_params={"subject": "aaa"}
        ).inbox_reports()

        assert [report.report_subject for report in reports] == [
            "Report subject 1 aaa",
            "Report subject 3 aaa",
        ]


class TestTriageReport:
    def test_attrs(self, requests_mock, triage_instance, fixture_from_file):
        requests_mock.get(
            "https://some-triage-host/api/public/v1/reports/6",
            text=fixture_from_file("single_report.json"),
        )

        report = TriageReport.fetch(triage_instance, "6")

        assert len(report.attrs) == 25
        assert report.id == 13363
        assert report.date == "2020-03-19T16:43:09.715Z"

    def test_reporter(self, mocker, requests_mock, triage_instance, fixture_from_file):
        requests_mock.get(
            "https://some-triage-host/api/public/v1/reports/6",
            text=fixture_from_file("single_report.json"),
        )
        stubbed_triagereporter_init = mocker.patch(
            "CofenseTriagev2.TriageReporter"
        )

        TriageReport.fetch(triage_instance, "6").reporter

        stubbed_triagereporter_init.assert_called_once_with(triage_instance, 5331)

    def test_attachment_none(self, requests_mock, triage_instance, fixture_from_file):
        requests_mock.get(
            "https://some-triage-host/api/public/v1/reports/6",
            text=fixture_from_file("single_report.json"),
        )

        report = TriageReport.fetch(triage_instance, "6")

        assert report.attachment is None

    def test_attachment_present(
            self, mocker, requests_mock, triage_instance, fixture_from_file
    ):
        requests_mock.get(
            "https://some-triage-host/api/public/v1/reports/6",
            text=fixture_from_file("single_report_with_attachment.json"),
        )

        report = TriageReport.fetch(triage_instance, "6")
        attachment = report.attachment

        assert attachment == {"path": "/path/to/temp/file", "name": "13363-report.html"}


class TestTriageReporter:
    def test_init(self, requests_mock, triage_instance, fixture_from_file):
        requests_mock.get(
            "https://some-triage-host/api/public/v1/reporters/5",
            text=fixture_from_file("reporters.json"),
        )

        reporter = TriageReporter(triage_instance, 5)

        assert reporter.attrs["email"] == "reporter1@example.com"

    def test_exists(self, requests_mock, triage_instance, fixture_from_file):
        requests_mock.get(
            "https://some-triage-host/api/public/v1/reporters/5",
            text=fixture_from_file("reporters.json"),
        )
        requests_mock.get(
            "https://some-triage-host/api/public/v1/reporters/6", text="[]"
        )

        assert TriageReporter(triage_instance, 5).exists() is True
        assert TriageReporter(triage_instance, 6).exists() is False
