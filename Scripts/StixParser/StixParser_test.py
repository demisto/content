import json

import pytest

import demistomock as demisto

""" helper functions """


def _get_results_from_demisto(entry, func, mocker):
    mock_demisto(mocker)
    try:
        func(entry)
        return demisto.results.call_args[0][0]
    except IndexError:
        pytest.fail(
            "Couldn't find results returned from Demisto", pytrace=True
        )


def mock_demisto(mocker):
    mocker.patch.object(demisto, 'results')


class TestGetIndicators:
    @staticmethod
    def _get_stix(
            stix2="./TestData/little_stix2.json",
            stix2_results="./TestData/little_stix2_results.json"):
        with open(stix2) as f:
            stix_input = json.load(f)

        with open(stix2_results) as f:
            expected_output = json.load(f)

        return stix_input, expected_output

    def _get_stix_little(self):
        return self._get_stix(
            "./TestData/little_stix2.json",
            "./TestData/little_stix2_results.json"
        )

    def test_get_indicators(self):
        from StixParser import get_indicators

        stix_input, expected_output = self._get_stix()

        output_dict, stix_objects = get_indicators(stix_input)

        assert (output_dict == expected_output[0]
                and stix_objects == expected_output[1]), "Output from Demisto didn't match the expected output"

    def test_get_indicators_dict(self):
        from StixParser import get_indicators

        stix_input, expected_output = self._get_stix_little()

        output, _ = get_indicators(stix_input[0])
        output_url = output.get("URL")
        expected_url = expected_output[0].get("URL")
        assert output_url == expected_url, "Output from Demisto didn't match the expected output\nExpected: {} \n " \
                                           "Got: {}".format(expected_url, output_url
                                                            )


class TestSTIX2ToDemisto:
    def test_stix2_to_demisto(self, mocker):
        from StixParser import stix2_to_demisto
        with open("./TestData/stix2.json") as f:
            js = json.load(f)
        try:
            d_results = _get_results_from_demisto(js, stix2_to_demisto, mocker)
            d_results = json.loads(d_results)
            assert isinstance(d_results, list)
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

        assert result_counter == results_length, "Results from expected file are {} but got {} " \
                                                 "results from script.".format(results_length, result_counter)

    def test_stix2_to_json_empty_case(self, mocker):
        from StixParser import stix2_to_demisto
        # Empty case
        res = _get_results_from_demisto([], stix2_to_demisto, mocker)
        assert res, "Sent empty JSON but got a response"
