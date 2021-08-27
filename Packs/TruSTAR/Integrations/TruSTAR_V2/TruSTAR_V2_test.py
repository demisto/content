import pytest
from TruSTAR_V2 import TrustarClient, Utils

import trustar
from trustar.models.indicator import Indicator
from trustar.models.enclave import EnclavePermissions
from trustar.models.report import Report
from trustar.models.intelligence_source import IntelligenceSource
from trustar.models.phishing_submission import PhishingSubmission, PhishingIndicator
from trustar.models.indicator_summary import IndicatorSummary, IndicatorAttribute, IndicatorScore


@pytest.fixture
def client():
    client = client = TrustarClient(config={
        'user_api_key': "test_api_key",
        'user_api_secret': "test_api_secret",
        'api_endpoint': "test_api_endpoint",
        'client_type': "Python_SDK",
        'client_metatag': "demisto-xsoar"
    })
    return client


@pytest.fixture
def enclaves():
    return [
        EnclavePermissions(
            id="931a7386-ed4f-4acd-bda0-b13b2b6b823f71",
            name="TestEnclave",
            type="CLOSED",
            read=True,
            create=False,
            update=True
        )
    ]


@pytest.fixture
def related_indicators(mocker):
    return mocker.Mock(
        items=[
            Indicator(
                type="SHA256",
                value="a127d88fb73f8f1a3671557f3084d02d981396d5f5218163ef26d61314ced3c1"
            ),
            Indicator(
                type="URL",
                value="www.testUrl.com"
            )
        ]
    )


@pytest.fixture
def trending_indicators():
    return [
        Indicator(
            correlation_count=724,
            type="URL",
            value="badware.info"
        ),
        Indicator(
            correlation_count=694,
            type="URL",
            value="botvrij.eu"
        )
    ]


@pytest.fixture
def indicators_metadata():
    return [
        Indicator(
            value="185.220.101.141",
            first_seen=1588884576620,
            last_seen=1588923302059,
            correlation_count=0,
            type="IP",
            enclave_ids=[
                '011ad71b-fd7d-44c2-834a-0d751299fb1f',
                '71f337a0-9696-4331-988a-5679271656a0',
                'd915e45a-d0c8-4a75-987a-775649020c96'
            ]
        )
    ]


@pytest.fixture
def indicator_summaries(mocker):
    return mocker.Mock(
        items=[
            IndicatorSummary(
                value="185.220.101.141",
                indicator_type="IP",
                source=IntelligenceSource(key="virustotal", name="VirusTotal"),
                severity_level=3,
                updated=1589782796000,
                enclave_id='011ad71b-fd7d-44c2-834a-0d751299fb1f',
                report_id='67c60023-83ea-4376-960e-2ff8fc9fbd33',
                attributes=[
                    IndicatorAttribute(
                        description='Number of associated URLs detected as bad',
                        name='Detected URLs',
                        value=1,
                    ),
                    IndicatorAttribute(
                        description='Number of hostnames this IP resolved to',
                        name='Hostname Resolutions',
                        value=2,
                    ),
                    IndicatorAttribute(
                        name='ASN',
                        value='200052',
                    ),
                ],
                score=IndicatorScore(name="Positives/Total Scans", value="64/75")
            ),
            IndicatorSummary(
                value="185.220.100.141",
                indicator_type="IP",
                source=IntelligenceSource(key="OTRO", name="VirusTotal"),
                severity_level=3,
                updated=1589782796000,
                enclave_id='011ad71b-fd7d-44c2-834a-0d751299fb1f',
                report_id='67c60023-83ea-4376-960e-2ff8fc9fbd33',
                attributes=[
                    IndicatorAttribute(
                        description='Number of associated URLs detected as bad',
                        name='Detected URLs',
                        value=1,
                    ),
                    IndicatorAttribute(
                        description='Number of hostnames this IP resolved to',
                        name='Hostname Resolutions',
                        value=2,
                    ),
                    IndicatorAttribute(
                        name='ASN',
                        value='200052',
                    ),
                ],
                score=IndicatorScore(name="Positives/Total Scans", value="64/75")
            )
        ]
    )


@pytest.fixture
def reports(mocker):
    return mocker.MagicMock(
        items=[
            Report(
                id="1",
                title="Test Report",
                body="Test Body",
            ),
            Report(
                id="2",
                title="Test Report2",
                body="{'testField': 'test'}",
            ),
        ]
    )


@pytest.fixture
def correlated_reports(mocker):
    return [
        Report(
            id="1",
            title="Test Report",
            body="Test Body",
        ),
        Report(
            id="2",
            title="Test Report2",
            body="{'testField': 'test'}",
        ),
    ]


@pytest.fixture
def whitelisted_indicators(mocker):
    return mocker.Mock(
        items=[
            Indicator(
                type="MD5",
                value="1e82dd741e908d02e4eff82461f1297e"
            ),
            Indicator(
                type="EMAIL_ADDRESS",
                value="truphish1337@gmail.com"
            )
        ]
    )


@pytest.fixture
def phishing_submissions(mocker):
    return mocker.Mock(
        items=[
            PhishingSubmission(
                submission_id="TEST-SUBMISSION-ID",
                title="TEST PHISHING SUBMISSION",
                priority_event_score=3,
                status="UNRESOLVED"
            )
        ]
    )


@pytest.fixture
def phishing_indicators(mocker):
    return mocker.Mock(
        items=[
            PhishingIndicator(
                indicator_type="URL",
                value="www.test.com",
                source_key="test_source",
                normalized_indicator_score=3,
                original_indicator_score=3
            )
        ]
    )


def test_get_enclaves(client, enclaves, monkeypatch):

    def mock_get_enclaves(*args, **kwargs):
        return enclaves

    monkeypatch.setattr(trustar.TruStar, "get_user_enclaves", mock_get_enclaves)
    response = client.get_enclaves()
    expected = enclaves[0].to_dict(remove_nones=True)

    assert response.get('Contents')[0] == expected


def test_related_indicators(client, related_indicators, monkeypatch):

    def mock_get_related_indicators(*args, **kwargs):
        return related_indicators

    monkeypatch.setattr(trustar.TruStar, "get_related_indicators_page", mock_get_related_indicators)
    indicators = ["a127d88fb73f8f1a3671557f3084d02d981396d5f5218163ef26d61314ced3c1", "www.testUrl.com"]
    response = client.get_related_indicators(indicators)

    expected = [i.to_dict(remove_nones=True) for i in related_indicators.items]
    assert response[0].get('Contents') == expected


def test_trending_indicators(client, trending_indicators, monkeypatch):

    def mock_get_trending_indicators(*args, **kwargs):
        return trending_indicators

    monkeypatch.setattr(trustar.TruStar, "get_community_trends", mock_get_trending_indicators)
    response = client.get_trending_indicators()
    expected = [i.to_dict(remove_nones=True) for i in trending_indicators]

    assert response[0].get('Contents') == expected


def test_get_indicators_metadata(client, indicators_metadata, monkeypatch):

    def mock_get_metadata(*args, **kwargs):
        return indicators_metadata

    monkeypatch.setattr(trustar.TruStar, "get_indicators_metadata", mock_get_metadata)
    response = client.get_indicators_metadata(indicators=['185.220.101.141'])
    expected = indicators_metadata[0].to_dict(remove_nones=True)
    expected["firstSeen"] = Utils.normalize_time(expected.get('firstSeen'))
    expected["lastSeen"] = Utils.normalize_time(expected.get('lastSeen'))

    assert response[0].get('Contents')[0] == expected


def test_get_indicator_summaries(client, indicator_summaries, monkeypatch):

    def mock_get_summaries(*args, **kwargs):
        return indicator_summaries

    monkeypatch.setattr(trustar.TruStar, "get_indicator_summaries_page", mock_get_summaries)
    response = client.get_indicator_summaries(values=['185.220.101.141'])
    expected = indicator_summaries.items[0].to_dict(remove_nones=True)
    expected['indicatorType'] = expected.pop('type')

    assert response[0].get('Contents')[0] == expected


def test_get_whitelisted_indicators(client, whitelisted_indicators, monkeypatch):

    def mock_get_whitelist(*args, **kwargs):
        return whitelisted_indicators

    monkeypatch.setattr(trustar.TruStar, "get_whitelist_page", mock_get_whitelist)
    response = client.get_whitelist()
    expected = [i.to_dict(remove_nones=True) for i in whitelisted_indicators.items]

    assert response[0].get('Contents') == expected


def test_get_indicators_for_report(client, whitelisted_indicators, monkeypatch):

    def mock_get_indicators_for_report(*args, **kwargs):
        return whitelisted_indicators

    monkeypatch.setattr(trustar.TruStar, "get_indicators_for_report_page", mock_get_indicators_for_report)
    response = client.get_indicators_for_report("76cc1321-f630-test-b82b-eb00a9022445")
    expected = [i.to_dict(remove_nones=True) for i in whitelisted_indicators.items]

    assert response[0].get('Contents') == expected


def test_move_report(client, monkeypatch):

    def mock_move_report(*args, **kwargs):
        return kwargs["report_id"]

    report_id = "94a476d8-17e3-490a-9020-f6971b692daf"
    enclave_id = "6ef1078c-a74a-4b42-9344-56c6adea0bda"
    monkeypatch.setattr(trustar.TruStar, "move_report", mock_move_report)
    response = client.move_report(report_id, enclave_id)

    assert response == f"{report_id} has been moved to enclave id: {enclave_id}"


def test_copy_report(client, monkeypatch):

    def mock_copy_report(*args, **kwargs):
        return "NEW-Test-ID"

    report_id = "94a476d8-17e3-490a-9020-f6971b692daf"
    dest_enclave_id = "6ef1078c-a74a-4b42-9344-56c6adea0bda"
    monkeypatch.setattr(trustar.TruStar, "copy_report", mock_copy_report)
    response = client.copy_report(report_id, dest_enclave_id)

    assert response == f"{report_id} has been copied to enclave id: {dest_enclave_id} with id: NEW-Test-ID"


def test_get_reports(client, reports, monkeypatch):

    def mock_get_reports(*args, **kwargs):
        return reports

    monkeypatch.setattr(trustar.TruStar, "get_reports_page", mock_get_reports)
    response = client.get_reports()
    expected = [report.to_dict(remove_nones=True) for report in reports.items]
    for e in expected:
        e["reportDeepLink"] = client.get_report_deep_link(e.get("id"))

    assert response.get('Contents') == expected


def test_get_report_details(client, reports, monkeypatch):
    def mock_get_report_details(*args, **kwargs):
        return reports.items[0]

    monkeypatch.setattr(trustar.TruStar, "get_report_details", mock_get_report_details)
    response = client.get_report_details(report_id="1")
    expected = reports.items[0].to_dict(remove_nones=True)
    expected['reportDeepLink'] = client.get_report_deep_link("1")

    assert response.get('Contents') == expected


def test_update_report(client, reports, monkeypatch):

    def mock_update_report(*args, **kwargs):
        return reports.items[0]

    monkeypatch.setattr(trustar.TruStar, "get_report_details", mock_update_report)
    monkeypatch.setattr(trustar.TruStar, "update_report", lambda x, y: None)
    response = client.update_report(report_id="1", title="NEW TEST TITLE")
    expected = reports.items[0].to_dict()
    expected['reportDeepLink'] = client.get_report_deep_link("1")
    expected['title'] = "NEW TEST TITLE"

    assert response.get('Contents') == expected


def test_search_reports(client, reports, monkeypatch):

    def mock_search_reports(*args, **kwargs):
        return reports.items

    monkeypatch.setattr(trustar.TruStar, "search_reports_page", mock_search_reports)
    response = client.search_reports()
    expected = [r.to_dict(remove_nones=True) for r in reports.items]

    assert response.get('Contents') == expected


def test_delete_report(client, monkeypatch):

    report_id = "94a476d8-17e3-490a-9020-f6971b692daf"
    monkeypatch.setattr(trustar.TruStar, "delete_report", lambda x, y, z: None)
    response = client.delete_report(report_id)

    assert response == f"Report {report_id} was successfully deleted"


def test_submit_report(client, monkeypatch, mocker):

    m = mocker.Mock(id=1)

    monkeypatch.setattr(trustar.TruStar, "submit_report", lambda x, y: m)
    response = client.submit_report(
        title="Test enclave",
        report_body="TEST BODY",
        enclave_ids=["testEnclaveId"]
    )

    assert response.get('Contents').get('id') == 1
    assert response.get('Contents').get('title') == "Test enclave"
    assert response.get('Contents').get('reportBody') == "TEST BODY"


def test_add_to_whitelist(client, monkeypatch):

    monkeypatch.setattr(trustar.TruStar, "add_terms_to_whitelist", lambda x, y: y)
    indicators = ["test@trustar.co", "www.testUrl.com"]
    response = client.add_to_whitelist(indicators)

    assert response == f"{indicators} added to the whitelist successfully"


def test_remove_from_whitelist(client, monkeypatch):

    monkeypatch.setattr(trustar.TruStar, "delete_indicator_from_whitelist", lambda x, y: None)
    indicator = "htain@trustar.co"
    response = client.remove_from_whitelist(indicator)
    assert response == f'{indicator} removed from the whitelist successfully'


def test_correlated_reports(client, correlated_reports, monkeypatch):

    def mock_get_correlated_reports(*args, **kwargs):
        return correlated_reports

    monkeypatch.setattr(trustar.TruStar, "get_correlated_reports_page", mock_get_correlated_reports)
    response = client.get_correlated_reports(indicators="5f67fc0a85ef8f1b6c17ee54acb55140")
    expected = [r.to_dict(remove_nones=True) for r in correlated_reports]

    assert response.get('Contents') == expected


def test_get_all_phishing_indicators(client, phishing_indicators, monkeypatch):

    def mock_get_phishing_indicators(*args, **kwargs):
        return phishing_indicators

    monkeypatch.setattr(trustar.TruStar, "get_phishing_indicators_page", mock_get_phishing_indicators)
    response = client.get_all_phishing_indicators()
    expected = phishing_indicators.items[0].to_dict(remove_nones=True)

    assert response[0].get('Contents')[0] == expected


def test_get_phishing_submissions(client, phishing_submissions, monkeypatch):

    def mock_get_phishing_submissions(*args, **kwargs):
        return phishing_submissions

    monkeypatch.setattr(trustar.TruStar, "get_phishing_submissions_page", mock_get_phishing_submissions)
    response = client.get_phishing_submissions()
    expected = phishing_submissions.items[0].to_dict(remove_nones=True)

    assert response.get('Contents')[0] == expected


def test_set_triage_status(client, monkeypatch, mocker):

    m = mocker.Mock()
    m.raise_for_status = lambda: None
    monkeypatch.setattr(trustar.TruStar, "mark_triage_status", lambda x, y, z: m)
    response = client.set_triage_status("TEST-ID", "RESOLVED")

    assert response == "Submission ID TEST-ID is RESOLVED"


def test_search_indicators(client, whitelisted_indicators, monkeypatch):

    def mock_search_indicators(*args, **kwargs):
        return whitelisted_indicators.items

    monkeypatch.setattr(trustar.TruStar, "search_indicators_page", mock_search_indicators)
    response = client.search_indicators()
    expected = [i.to_dict(remove_nones=True) for i in whitelisted_indicators.items]

    assert response[0].get('Contents') == expected
