from CofenseTriagev2.CofenseTriage import TriageReporter


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
