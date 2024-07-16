import json
from ReversingLabsTitaniumCloudv2 import file_reputation_output, av_scanners_output, file_analysis_output, \
    rha1_analytics_output, uri_statistics_output, url_report_output, imphash_similarity_output, classification_to_score, \
    analyze_url_output, detonate_sample_output, yara_matches_feed_output, yara_retro_matches_feed_output, \
    functional_similarity_output, uri_index_output, advanced_search_output, expression_search_output, \
    sample_dynamic_analysis_results_output, certificate_analytics_output, reanalyze_sample_output, url_downloaded_files_output, \
    url_latest_analyses_feed_output, url_analyses_feed_from_date_output, yara_ruleset_output, yara_retro_actions_output, \
    format_proxy, domain_report_output, domain_downloaded_files_output, domain_urls_output, domain_to_ip_output, \
    domain_related_domains_output, ip_report_output, ip_downloaded_files_output, ip_urls_output, ip_to_domain_output, \
    network_reputation_output, detonate_url_output, url_dynamic_analysis_results_output, customer_usage_data_output
import demistomock as demisto
import pytest

INTEGRATION_NAME = 'ReversingLabs TitaniumCloud v2'
test_hash = "21841b32c6165b27dddbd4d6eb3a672defe54271"
url = "google.com"
CLASSIFICATION = "MALICIOUS"
url2 = "https://www.imdb.com/title/tt7740510/reviews?ref_=tt_urv"
sha1 = "efabc8b39de9d1f136abc48dc6e47f30a2ce9245"
thumbprint = "A481635184832F09BC3D3921A335634466C4C6FC714D8BBD89F65E827E5AF1B1"


@pytest.fixture(autouse=True)
def handle_calling_context(mocker):
    mocker.patch.object(demisto, 'callingContext', {'context': {'IntegrationBrand': INTEGRATION_NAME}})


def load_json(file_path):
    with open(file_path, encoding="utf-8") as file_handle:
        return json.loads(file_handle.read())


def test_file_reputation_output():
    test_report = load_json("test_data/file_reputation_report.json")
    test_context = load_json("test_data/file_reputation_context.json")

    result = file_reputation_output(response_json=test_report, hash_value=test_hash)

    assert result.to_context() == test_context


def test_av_scanners_output():
    test_report = load_json("test_data/av_scanners_report.json")
    test_context = load_json("test_data/av_scanners_context.json")

    result = av_scanners_output(response_json=test_report, hash_value=test_hash)

    assert result.to_context() == test_context


def test_file_analysis_output():
    test_report = load_json("test_data/file_analysis_report.json")
    test_context = load_json("test_data/file_analysis_context.json")

    result = file_analysis_output(response_json=test_report, hash_value=test_hash)

    assert result.to_context() == test_context


def test_rha1_analytics_output():
    test_report = load_json("test_data/rha1_analytics_report.json")
    test_context = load_json("test_data/rha1_analytics_context.json")

    result = rha1_analytics_output(response_json=test_report, hash_value=test_hash)

    assert result.to_context() == test_context


def test_uri_statistics_output():
    test_report = load_json("test_data/uri_statistics_report.json")
    test_context = load_json("test_data/uri_statistics_context.json")

    result = uri_statistics_output(response_json=test_report, uri=url)

    assert result.to_context() == test_context


def test_url_report_output():
    test_report = load_json("test_data/url_report_report.json")
    test_context = load_json("test_data/url_report_context.json")

    result = url_report_output(response_json=test_report, url=url)

    assert result.to_context() == test_context


def test_imphash_similarity_output():
    test_report = load_json("test_data/imphash_report.json")
    test_context = load_json("test_data/imphash_context.json")

    result = imphash_similarity_output(imphash="f34d5f2d4577ed6d9ceec516c1f5a744", response=test_report)

    assert result.to_context() == test_context


def test_classification_to_score():
    score = classification_to_score(CLASSIFICATION)

    assert score == 3


def test_analyze_url_output():
    test_report = load_json("test_data/analyze_url.json")
    test_context = load_json("test_data/analyze_url_context.json")

    result = analyze_url_output(response_json=test_report, url=url2)

    assert result.to_context() == test_context


def test_yara_matches_feed_output():
    test_report = load_json("test_data/yara_feed.json")
    test_context = load_json("test_data/yara_feed_context.json")

    result = yara_matches_feed_output(response_json=test_report, time_value="1688563828")

    assert result.to_context() == test_context


def test_yara_retro_matches_feed_output():
    test_report = load_json("test_data/yara_retro.json")
    test_context = load_json("test_data/yara_retro_context.json")

    result = yara_retro_matches_feed_output(response_json=test_report, time_value="1688563828")

    assert result.to_context() == test_context


def test_functional_similarity_output():
    test_report = load_json("test_data/functional_similarity.json")
    test_context = load_json("test_data/functional_similarity_context.json")

    result = functional_similarity_output(sha1_list=test_report)

    assert result.to_context() == test_context


def test_uri_index_output():
    test_report = load_json("test_data/uri_index.json")
    test_context = load_json("test_data/uri_index_context.json")

    result, _ = uri_index_output(sha1_list=test_report, uri=url)

    assert result.to_context() == test_context


def test_advanced_search_output():
    test_report = load_json("test_data/advanced_search.json")
    test_context = load_json("test_data/advanced_search_context.json")

    result, _ = advanced_search_output(result_list=test_report)

    assert result.to_context() == test_context


def test_expression_search_output():
    test_report = load_json("test_data/expression_search.json")
    test_context = load_json("test_data/expression_search_context.json")

    result, _ = expression_search_output(result_list=test_report)

    assert result.to_context() == test_context


def test_certificate_analytics_output():
    test_report = load_json("test_data/certificate_analytics.json")
    test_context = load_json("test_data/certificate_analytics_context.json")

    result, _ = certificate_analytics_output(response_json=test_report, thumbprint=thumbprint)

    assert result.to_context() == test_context


def test_reanalyze_sample_output():
    report_text = "Sample sent for rescanning"
    test_context = load_json("test_data/reanalyze_sample_context.json")

    result = reanalyze_sample_output(report_text)

    assert result.to_context() == test_context


def test_url_downloaded_files_output():
    test_report = load_json("test_data/url_downloaded_files.json")
    test_context = load_json("test_data/url_downloaded_files_context.json")

    result = url_downloaded_files_output(test_report, "https://sniper.ursula-bilgeri.at/")

    assert result.to_context() == test_context


def test_url_latest_analyses_feed_output():
    test_report = load_json("test_data/url_latest_analyses.json")
    test_context = load_json("test_data/url_latest_analyses_context.json")

    result, _ = url_latest_analyses_feed_output(test_report)

    assert result.to_context() == test_context


def test_url_analyses_feed_from_date_output():
    test_report = load_json("test_data/url_analyses_date.json")
    test_context = load_json("test_data/url_analyses_date_context.json")

    result, _ = url_analyses_feed_from_date_output(test_report, "1688913146")

    assert result.to_context() == test_context


def test_yara_ruleset_output_info():
    test_report = load_json("test_data/yara_ruleset_info.json")
    test_context = load_json("test_data/yara_ruleset_info_context.json")

    result = yara_ruleset_output("get_yara_ruleset_info", test_report)

    assert result.to_context() == test_context


def test_yara_retro_output_status():
    test_report = load_json("test_data/yara_retro_status.json")
    test_context = load_json("test_data/yara_retro_status_context.json")

    result = yara_retro_actions_output("check_yara_retro_status", test_report)

    assert result.to_context() == test_context


def test_format_proxy():
    formatted_correctly = format_proxy(
        addr="https://proxy-address.com",
        username="user1",
        password="pass1"
    )

    correct_expected = "https://user1:pass1@proxy-address.com"

    assert formatted_correctly == correct_expected


def test_domain_report_output():
    test_report = load_json("test_data/domain_report.json")
    test_context = load_json("test_data/domain_report_context.json")

    result = domain_report_output(test_report, "bloom-artists.com")

    assert result.to_context() == test_context


def test_domain_downloaded_files_output():
    test_report = load_json("test_data/domain_downloaded_files.json")
    test_context = load_json("test_data/domain_downloaded_files_context.json")

    result = domain_downloaded_files_output(test_report, "bloom-artists.com")

    assert result.to_context() == test_context


def test_domain_urls_output():
    test_report = load_json("test_data/domain_urls.json")
    test_context = load_json("test_data/domain_urls_context.json")

    result = domain_urls_output(test_report, "bloom-artists.com")

    assert result.to_context() == test_context


def test_domain_to_ip_output():
    test_report = load_json("test_data/domain_to_ip.json")
    test_context = load_json("test_data/domain_to_ip_context.json")

    result = domain_to_ip_output(test_report, "bloom-artists.com")

    assert result.to_context() == test_context


def test_domain_related_domains_output():
    test_report = load_json("test_data/domain_related_domains.json")
    test_context = load_json("test_data/domain_related_domains_context.json")

    result = domain_related_domains_output(test_report, "smsv4.ufcfan.org")

    assert result.to_context() == test_context


def test_ip_report_output():
    test_report = load_json("test_data/ip_report.json")
    test_context = load_json("test_data/ip_report_context.json")

    result = ip_report_output(test_report, "5.42.64.70")

    assert result.to_context() == test_context


def test_ip_downloaded_files_output():
    test_report = load_json("test_data/ip_downloaded_files.json")
    test_context = load_json("test_data/ip_downloaded_files_context.json")

    result = ip_downloaded_files_output(test_report, "61.253.71.111")

    assert result.to_context() == test_context


def test_ip_urls_output():
    test_report = load_json("test_data/ip_urls.json")
    test_context = load_json("test_data/ip_urls_context.json")

    result = ip_urls_output(test_report, "61.253.71.111")

    assert result.to_context() == test_context


def test_ip_to_domain_output():
    test_report = load_json("test_data/ip_to_domain.json")
    test_context = load_json("test_data/ip_to_domain_context.json")

    result = ip_to_domain_output(test_report, "61.253.71.111")

    assert result.to_context() == test_context


def test_network_reputation_output():
    test_report = load_json("test_data/network_reputation.json")
    test_context = load_json("test_data/network_reputation_context.json")

    result = network_reputation_output(test_report,
                                       ["http://43.138.221.139/jquery-3.3.1.min.js", "61.253.71.111", "bloom-artists.com"]
                                       )

    assert result.to_context() == test_context


def test_detonate_sample_output():
    test_report = load_json("test_data/detonate_sample.json")
    test_context = load_json("test_data/detonate_sample_context.json")

    result = detonate_sample_output(response_json=test_report, sha1=test_hash)

    assert result.to_context() == test_context


def test_sample_dynamic_analysis_results_output():
    test_report = load_json("test_data/sample_dynamic_response.json")
    test_context = load_json("test_data/sample_dynamic_context.json")

    result, _ = sample_dynamic_analysis_results_output(response_json=test_report, sha1=test_hash)

    assert result.to_context() == test_context


def test_detonate_url_output():
    test_report = load_json("test_data/detonate_url.json")
    test_context = load_json("test_data/detonate_url_context.json")

    result = detonate_url_output(response_json=test_report, url=url2)

    assert result.to_context() == test_context


def test_url_dynamic_analysis_results_output():
    test_report = load_json("test_data/url_dynamic_response.json")
    test_context = load_json("test_data/url_dynamic_context.json")

    result, _ = url_dynamic_analysis_results_output(
        response_json=test_report,
        passed_url="https://www.imdb.com/title/tt7740510/reviews?ref_=tt_urv"
    )

    assert result.to_context() == test_context


def test_customer_data_output():
    report = load_json("test_data/customer_usage_data.json")
    result = customer_usage_data_output(data_type="MONTHLY USAGE", whole_company=False, response_json=report)

    assert result.to_context().get("Contents").get("customer_usage_data").get("rl").get("month") == "2024-06"
