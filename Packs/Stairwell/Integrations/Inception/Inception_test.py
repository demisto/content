from Inception import Client, variant_discovery_command, file_enrichment_command
import json

API_KEY = "FAKEAPIKEY"
TEST_FILE_HASH = "e7762f90024c5366807c7c145d3456f0ac3be086c0ec3557427d3c2c10a2052d"


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


test_client = Client(
    base_url='https://fakeapi.stairwelldemo.com',
    verify=False,
    proxy=False,
    headers={"Authorization": API_KEY}
)


def test_variant_discovery_command_success(requests_mock):
    mock_response = util_load_json('test_data/variant_discovery_command_result.json')

    requests_mock.get("https://fakeapi.stairwelldemo.com/" + TEST_FILE_HASH, json=mock_response)

    results = variant_discovery_command(test_client, TEST_FILE_HASH)
    assert results


def test_variant_discovery_command_none(requests_mock):
    mock_response = util_load_json('test_data/variant_discovery_command_results_none.json')

    requests_mock.get("https://fakeapi.stairwelldemo.com/" + TEST_FILE_HASH, json=mock_response)

    results = variant_discovery_command(test_client, TEST_FILE_HASH)
    assert results


def test_variant_discovery_command_notfound(requests_mock):
    mock_response = util_load_json('test_data/variant_discovery_command_results_notfound.json')

    requests_mock.get("https://fakeapi.stairwelldemo.com/" + TEST_FILE_HASH, json=mock_response, status_code=500)

    results = variant_discovery_command(test_client, TEST_FILE_HASH)
    assert results


def test_file_enrichment_command(requests_mock):
    mock_response = util_load_json('test_data/file_enrichment_command_result.json')

    requests_mock.get("https://fakeapi.stairwelldemo.com/" + TEST_FILE_HASH, json=mock_response)

    results = file_enrichment_command(test_client, TEST_FILE_HASH)
    assert results
    assert results.outputs['data']['attributes']['mal_eval_result']['label'] == "onlinegames"
    assert results.outputs['data']['attributes']['mal_eval_result']['probability_bucket'] == "PROBABILITY_VERY_HIGH"
    assert "Seen_Assets: Ida Bear Sandbox(1), Ida Bear Sandbox2(1)" not in results.readable_output
    assert "Seen Assets: Ida Bear Sandbox(1)" in results.readable_output


def test_file_enrichment_command_multiple_occurrences(requests_mock):
    mock_response = util_load_json('test_data/file_enrichment_command_result_multiple_occurrences.json')

    requests_mock.get("https://fakeapi.stairwelldemo.com/" + TEST_FILE_HASH, json=mock_response)

    results = file_enrichment_command(test_client, TEST_FILE_HASH)
    assert results
    assert results.outputs['data']['attributes']['mal_eval_result']['label'] == "onlinegames"
    assert results.outputs['data']['attributes']['mal_eval_result']['probability_bucket'] == "PROBABILITY_VERY_HIGH"
    assert "Seen_Assets: Ida Bear Sandbox(1), Ida Bear Sandbox2(1)" in results.readable_output


def test_file_enrichment_command_notfound(requests_mock):
    mock_response = util_load_json('test_data/file_enrichment_command_result.json')

    requests_mock.get("https://fakeapi.stairwelldemo.com/" + TEST_FILE_HASH, json=mock_response, status_code=404)

    results = file_enrichment_command(test_client, TEST_FILE_HASH)
    assert results
