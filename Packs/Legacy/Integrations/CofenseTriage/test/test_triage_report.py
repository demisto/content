import pytest

from ..CofenseTriage import TriageReport


class TestTriageReport:
    def test_attrs(self, requests_mock, fixture_from_file):
        requests_mock.get(
            "https://some-triage-host/api/public/v1/reports/6",
            text=fixture_from_file("single_report.json"),
        )

        report = TriageReport.fetch("6")

        assert len(report.attrs) == 25
        assert report.id == 13363
        assert report.date == "2020-03-19T16:43:09.715Z"

    def test_reporter(self, mocker, requests_mock, fixture_from_file):
        requests_mock.get(
            "https://some-triage-host/api/public/v1/reports/6",
            text=fixture_from_file("single_report.json"),
        )
        stubbed_triagereporter_init = mocker.patch(
            "CofenseTriage.CofenseTriage.TriageReporter"
        )

        TriageReport.fetch("6").reporter

        stubbed_triagereporter_init.assert_called_once_with(5331)

    def test_attachment_none(self, requests_mock, fixture_from_file):
        requests_mock.get(
            "https://some-triage-host/api/public/v1/reports/6",
            text=fixture_from_file("single_report.json"),
        )

        report = TriageReport.fetch("6")

        assert report.attachment is None

    def test_attachment_present(self, mocker, requests_mock, fixture_from_file):
        requests_mock.get(
            "https://some-triage-host/api/public/v1/reports/6",
            text=fixture_from_file("single_report_with_attachment.json"),
        )

        mocker.patch(
            "CofenseTriage.CofenseTriage.fileResult",
            lambda **_kwargs: {
                "FileID": "file_result_id",
                "FileName": "file_result_name",
            },
        )

        report = TriageReport.fetch("6")
        attachment = report.attachment

        assert attachment == {"path": "file_result_id", "name": "file_result_name"}
