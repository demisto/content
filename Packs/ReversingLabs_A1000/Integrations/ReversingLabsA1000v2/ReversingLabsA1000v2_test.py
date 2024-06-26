import json
from ReversingLabsA1000v2 import a1000_report_output, list_extracted_files_output, get_classification_output, \
    classification_to_score, url_report_output, domain_report_output, ip_report_output, format_proxy, \
    file_analysis_status_output, pdf_report_output, static_analysis_report_output, dynamic_analysis_report_output, \
    sample_classification_output, yara_output, yara_retro_output, list_containers_output, upload_from_url_output, \
    delete_sample_output, reanalyze_output, advanced_search_output, VERSION, USER_AGENT, RELIABILITY, upload_sample_output, \
    HTTP_PROXY, HTTP_PROXY_USERNAME, HTTP_PROXY_PASSWORD, HOST, TOKEN
import demistomock as demisto
import pytest

INTEGRATION_NAME = 'ReversingLabs A1000'


@pytest.fixture(autouse=True)
def handle_calling_context(mocker):
    mocker.patch.object(demisto, 'callingContext', {'context': {'IntegrationBrand': INTEGRATION_NAME}})


def test_a1000_report_output():
    test_response = util_load_json('test_data/a1000_response.json')
    test_context = util_load_json('test_data/a1000_context.json')

    result = a1000_report_output(test_response)

    assert result.to_context() == test_context


def test_a1000_list_extracted_output():
    test_response = util_load_json('test_data/a1000_list_extracted_response.json')
    test_context = util_load_json('test_data/a1000_list_extracted_context.json')

    result = list_extracted_files_output(test_response)

    assert result.to_context() == test_context


def test_a1000_get_classification_output():
    test_response = util_load_json('test_data/a1000_get_classification_response.json')
    test_context = util_load_json('test_data/a1000_get_classification_context.json')

    result = get_classification_output(test_response)

    assert result.to_context() == test_context


def test_url_report_output():
    test_response = util_load_json("test_data/a1000_url_report.json")
    test_context = util_load_json("test_data/a1000_url_report_context.json")

    result = url_report_output(url="http://195.133.11.16/push", response_json=test_response)

    assert result.to_context() == test_context


def test_domain_report_output():
    test_response = util_load_json("test_data/a1000_domain_report.json")
    test_context = util_load_json("test_data/a1000_domain_report_context.json")

    result = domain_report_output(domain="index.hr", response_json=test_response)

    assert result.to_context() == test_context


def test_ip_report_output():
    test_response = util_load_json("test_data/a1000_ip_report.json")
    test_context = util_load_json("test_data/a1000_ip_report_context.json")

    result = ip_report_output(ip="8.8.4.4", response_json=test_response)

    assert result.to_context() == test_context


def test_file_analysis_status_output():
    test_response = util_load_json("test_data/a1000_analysis_status.json")

    result = file_analysis_status_output(resp_json=test_response)

    for k, v in result.to_context().items():
        if k == "hash_value":
            assert v == "d1aff4d205b59b1ae3edf152603fa2ae5a7c6cc5"


def test_pdf_report_output():
    test_response = util_load_json("test_data/a1000_pdf_report.json")

    result = pdf_report_output(resp=test_response, sample_hash="d1aff4d205b59b1ae3edf152603fa2ae5a7c6cc5", action="CHECK STATUS")

    for k, v in result[0].to_context().items():
        if k == "status":
            assert v == 2


def test_static_analysis_report_output():
    test_response = util_load_json("test_data/a1000_static_analysis.json")

    result = static_analysis_report_output(resp_json=test_response, sample_hash="d1aff4d205b59b1ae3edf152603fa2ae5a7c6cc5")

    for k, v in result.to_context().items():
        if k == "Contents":
            assert "a1000_static_analysis_report" in v


def test_dynamic_analysis_report_output():
    test_response = util_load_json("test_data/a1000_dynamic_analysis.json")

    result = dynamic_analysis_report_output(resp=test_response, action="CHECK STATUS", report_format="pdf",
                                            sample_hash="d1aff4d205b59b1ae3edf152603fa2ae5a7c6cc5")

    for k, v in result[0].to_context().items():
        if k == "status":
            assert v == 1


def test_sample_classification_output():
    test_response = util_load_json("test_data/a1000_sample_classification.json")

    result = sample_classification_output(resp_json=test_response, action="GET CLASSIFICATION", av_scanners=False,
                                          sample_hash="d1aff4d205b59b1ae3edf152603fa2ae5a7c6cc5")

    for k, v in result.to_context().items():
        if k == "Contents":
            assert "a1000_sample_classification" in v


def test_yara_output():
    rulesets = util_load_json("test_data/a1000_yara_get_rulesets.json")
    contents = util_load_json("test_data/a1000_yara_get_contents.json")

    result_rulesets = yara_output(resp_json=rulesets, action="GET RULESETS")
    result_contents = yara_output(resp_json=contents, action="GET CONTENTS")

    assert result_rulesets.to_context().get("Contents").get("a1000_yara").get("count") == 4
    assert result_contents.to_context().get("Contents").get("a1000_yara").get("detail").get("name") == "test_yara_rule"


def test_yara_retro_output():
    local = util_load_json("test_data/a1000_yara_retro_local.json")
    cloud = util_load_json("test_data/a1000_yara_retro_cloud.json")

    result_local = yara_retro_output(resp_json=local, action="LOCAL SCAN STATUS")
    result_cloud = yara_retro_output(resp_json=cloud, action="CLOUD SCAN STATUS")

    assert result_local.to_context().get("Contents").get("a1000_yara_retro").get("status").get("state") == "COMPLETED"
    assert result_cloud.to_context().get("Contents").get("a1000_yara_retro").get("status").get("cloud_status") == "ACTIVE"


def test_list_containers_output():
    containers = util_load_json("test_data/a1000_list_containers.json")
    result = list_containers_output(resp_json=containers)

    assert result.to_context().get("Contents").get("a1000_list_containers").get("count") == 0


def test_upload_from_url_output():
    upload = util_load_json("test_data/a1000_upload_from_url.json")
    report = util_load_json("test_data/a1000_report_from_url.json")
    check = util_load_json("test_data/a1000_check_from_url.json")

    result_upload = upload_from_url_output(resp_json=upload, action="UPLOAD")
    result_report = upload_from_url_output(resp_json=report, action="GET REPORT")
    result_check = upload_from_url_output(resp_json=check, action="CHECK ANALYSIS STATUS")

    assert result_upload.to_context().get("Contents").get("a1000_upload_from_url_actions").get("message") == "Done."
    assert result_report.to_context().get("Contents").get("a1000_upload_from_url_actions").get("processing_status") == "complete"
    assert result_check.to_context().get("Contents").get("a1000_upload_from_url_actions").get("processing_status") == "complete"


def test_delete_sample_output():
    report = util_load_json("test_data/a1000_delete_sample.json")
    result = delete_sample_output(response_json=report)

    assert result[0].to_context().get("Contents").get("a1000_delete_report").get("results").get("code") == 200


def test_reanalyze_output():
    report = util_load_json("test_data/a1000_reanalyze.json")
    result = reanalyze_output(response_json=report)

    assert (result[0].to_context().get("Contents").get("a1000_reanalyze_report").get("results")[0].get("detail").get("sha1")
            == "d1aff4d205b59b1ae3edf152603fa2ae5a7c6cc5")


def test_advanced_search_output():
    report = util_load_json("test_data/a1000_advanced_search.json")
    result = advanced_search_output(result_list=report)

    assert result[0].to_context().get("Contents").get("a1000_advanced_search_report")[0].get("available")


def test_classification_to_score():
    assert classification_to_score("MALICIOUS") == 3


def test_format_proxy():
    formatted_correctly = format_proxy(
        addr="https://proxy-address.com",
        username="user1",
        password="pass1"
    )

    formatted_http = format_proxy(
        addr="http://proxy-address.com",
        username="user1",
        password="pass1"
    )

    correct_expected = "https://user1:pass1@proxy-address.com"

    assert formatted_correctly == correct_expected
    assert formatted_http != correct_expected


def test_vars():
    assert "ReversingLabs XSOAR A1000 " + VERSION == USER_AGENT
    assert RELIABILITY is not None
    assert HTTP_PROXY is None
    assert HTTP_PROXY_USERNAME is None
    assert HTTP_PROXY_PASSWORD is None
    assert HOST is None
    assert TOKEN is None


def test_upload_sample_output():
    report = util_load_json("test_data/a1000_upload_sample.json")
    result = upload_sample_output(response_json=report)

    assert result[0].to_context().get("Contents").get("a1000_upload_report").get("message") == "Done."


def util_load_json(path):
    with open(path) as f:
        return json.loads(f.read())
