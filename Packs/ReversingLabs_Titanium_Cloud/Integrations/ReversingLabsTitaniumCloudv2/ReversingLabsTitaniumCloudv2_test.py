import json
from ReversingLabsTitaniumCloudv2 import file_reputation_output, av_scanners_output, file_analysis_output, \
    rha1_analytics_output, uri_statistics_output, url_report_output
import demistomock as demisto
import pytest

INTEGRATION_NAME = 'ReversingLabs TitaniumCloud v2'
test_hash = "21841b32c6165b27dddbd4d6eb3a672defe54271"
url = "google.com"


@pytest.fixture(autouse=True)
def handle_calling_context(mocker):
    mocker.patch.object(demisto, 'callingContext', {'context': {'IntegrationBrand': INTEGRATION_NAME}})


def load_json(file_path):
    with open(file_path, "r", encoding="utf-8") as file_handle:
        return json.loads(file_handle.read())


def test_file_reputation_output():
    test_report = load_json("TestData/file_reputation_report.json")
    test_context = load_json("TestData/file_reputation_context.json")

    result = file_reputation_output(response_json=test_report, hash_value=test_hash)

    assert result.to_context() == test_context


def test_av_scanners_output():
    test_report = load_json("TestData/av_scanners_report.json")
    test_context = load_json("TestData/av_scanners_context.json")

    result = av_scanners_output(response_json=test_report, hash_value=test_hash)

    assert result.to_context() == test_context


def test_file_analysis_output():
    test_report = load_json("TestData/file_analysis_report.json")
    test_context = load_json("TestData/file_analysis_context.json")

    result = file_analysis_output(response_json=test_report, hash_value=test_hash)

    assert result.to_context() == test_context


def test_rha1_analytics_output():
    test_report = load_json("TestData/rha1_analytics_report.json")
    test_context = load_json("TestData/rha1_analytics_context.json")

    result = rha1_analytics_output(response_json=test_report, hash_value=test_hash)

    assert result.to_context() == test_context


def test_uri_statistics_output():
    test_report = load_json("TestData/uri_statistics_report.json")
    test_context = load_json("TestData/uri_statistics_context.json")

    result = uri_statistics_output(response_json=test_report, uri=url)

    assert result.to_context() == test_context


def test_url_report_output():
    test_report = load_json("TestData/url_report_report.json")
    test_context = load_json("TestData/url_report_context.json")

    result = url_report_output(response_json=test_report, url=url)

    assert result.to_context() == test_context
