import json
from ReversingLabsTitaniumCloudv2 import file_reputation_output, av_scanners_output, file_analysis_output, \
    rha1_analytics_output, uri_statistics_output, url_report_output


test_hash = "21841b32c6165b27dddbd4d6eb3a672defe54271"
url = "google.com"


def test_file_reputation_output():
    test_report = json.load(open("TestData/file_reputation_report.json"))
    test_context = json.load(open("TestData/file_reputation_context.json"))

    result = file_reputation_output(response_json=test_report, hash_value=test_hash)

    assert result.to_context() == test_context


def test_av_scanners_output():
    test_report = json.load(open("TestData/av_scanners_report.json"))
    test_context = json.load(open("TestData/av_scanners_context.json"))

    result = av_scanners_output(response_json=test_report, hash_value=test_hash)

    assert result.to_context() == test_context


def test_file_analysis_output():
    test_report = json.load(open("TestData/file_analysis_report.json"))
    test_context = json.load(open("TestData/file_analysis_context.json"))

    result = file_analysis_output(response_json=test_report, hash_value=test_hash)

    assert result.to_context() == test_context


def test_rha1_analytics_output():
    test_report = json.load(open("TestData/rha1_analytics_report.json"))
    test_context = json.load(open("TestData/rha1_analytics_context.json"))

    result = rha1_analytics_output(response_json=test_report, hash_value=test_hash)

    assert result.to_context() == test_context


def test_uri_statistics_output():
    test_report = json.load(open("TestData/uri_statistics_report.json"))
    test_context = json.load(open("TestData/uri_statistics_context.json"))

    result = uri_statistics_output(response_json=test_report, uri=url)

    assert result.to_context() == test_context


def test_url_report_output():
    test_report = json.load(open("TestData/url_report_report.json"))
    test_context = json.load(open("TestData/url_report_context.json"))

    result = url_report_output(response_json=test_report, url=url)

    assert result.to_context() == test_context
