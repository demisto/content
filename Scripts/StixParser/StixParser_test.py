import json

import pytest

import demistomock as demisto


def mock_demisto(mocker):
    mocker.patch.object(demisto, 'results')


def test_get_indicators():
    from StixParser import get_indicators

    # Test list
    with open("./TestData/little_stix2.json") as f:
        stix_input = json.load(f)

    output_dict, stix_objects = get_indicators(stix_input)
    with open("./TestData/little_stix2_results.json") as f:
        expected_output = json.load(f)

    if not (output_dict == expected_output[0] and stix_objects == expected_output[1]):
        pytest.fail("Output from Demisto didn't match the expected output")

    # Test dict
    output, _ = get_indicators(stix_input[0])
    output_url = output.get("URL")
    expected_url = expected_output[0].get("URL")
    if output_url != expected_url:
        pytest.fail("Output from Demisto didn't match the expected output\n"
                    "Expected: {} \n Got: {}".format(expected_url, output_url))


def test_stix2_to_demisto(mocker):
    from StixParser import stix2_to_demisto
    mock_demisto(mocker)
    with open("./TestData/stix2.json") as f:
        js = json.load(f)
    stix2_to_demisto(js)
    try:
        d_results = demisto.results.call_args[0][0]
        d_results = json.loads(d_results)
        assert isinstance(d_results, list)
    except IndexError:
        pytest.fail(
            "Couldn't find results returned from Demisto", pytrace=True
        )
    except ValueError:
        pytest.fail(
            "Couldn't parse output as JSON", pytrace=True
        )
    with open("./TestData/stix2_results.json") as f:
        results = json.load(f)
        results_length = len(results)
        result_counter = 0
        for result in results:
            for result_demisto in d_results:
                if result == result_demisto:
                    result_counter += 1

    if result_counter != results_length:
        pytest.fail(
            "Results from expected file are {} but got {} results from script.".format(results_length, result_counter)
        )
