import json
from ReversingLabsTitaniumCloudv2 import file_reputation_output, av_scanners_output, file_analysis_output, \
    rha1_analytics_output, uri_statistics_output, url_report_output, imphash_similarity_output, classification_to_score, \
    analyze_url_output, detonate_sample_output, yara_matches_feed_output, yara_retro_matches_feed_output
import demistomock as demisto
import pytest

INTEGRATION_NAME = 'ReversingLabs TitaniumCloud v2'
test_hash = "21841b32c6165b27dddbd4d6eb3a672defe54271"
url = "google.com"
CLASSIFICATION = "MALICIOUS"
url2 = "https://www.imdb.com/title/tt7740510/reviews?ref_=tt_urv"
sha1 = "efabc8b39de9d1f136abc48dc6e47f30a2ce9245"


@pytest.fixture(autouse=True)
def handle_calling_context(mocker):
    mocker.patch.object(demisto, 'callingContext', {'context': {'IntegrationBrand': INTEGRATION_NAME}})


def load_json(file_path):
    with open(file_path, "r", encoding="utf-8") as file_handle:
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


def test_detonate_sample_output():
    test_report = load_json("test_data/detonate_sample.json")
    test_context = load_json("test_data/detonate_sample_context.json")

    result = detonate_sample_output(response_json=test_report, sha1=sha1)

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

