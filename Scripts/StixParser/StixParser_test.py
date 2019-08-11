import json

import pytest

import demistomock as demisto

""" helper functions """


def get_files_in_dir(mypath, only_with_ext=None):
    from os import listdir
    from os.path import isfile, join
    files_list = [f for f in listdir(mypath) if isfile(join(mypath, f))]
    if only_with_ext:
        return [f for f in files_list if f.endswith(only_with_ext)]
    return files_list


def mock_demisto(mocker):
    mocker.patch.object(demisto, 'results')


def _get_stix(
        stix2="./TestData/stix2.json",
        stix2_results="./TestData/stix2_results.json"):
    with open(stix2) as f:
        stix_input = json.load(f)

    with open(stix2_results) as f:
        expected_output = json.load(f)

    return stix_input, expected_output


def _get_stix_little():
    return _get_stix(
        "./TestData/little_stix2.json",
        "./TestData/little_stix2_results.json"
    )


def _get_results_from_demisto(entry, func, mocker):
    mock_demisto(mocker)
    try:
        func(entry)
        return demisto.results.call_args[0][0]
    except IndexError:
        pytest.fail(
            "Couldn't find results returned from Demisto", pytrace=True
        )


class TestGetIndicators:
    def test_get_indicators(self):
        err = "Output from Demisto didn't match the expected output"
        from StixParser import get_indicators

        stix_input, expected_output = _get_stix()
        stix_input = stix_input.get("objects")

        output_dict, stix_objects = get_indicators(stix_input)
        assert output_dict == expected_output[0], err
        assert stix_objects.get("8.8.8.8").get("pattern") == "[domain-name:value = 'ip-8-8-8-8']", err

    def test_get_indicators_dict(self):
        from StixParser import get_indicators

        stix_input, expected_output = _get_stix_little()

        output, _ = get_indicators(stix_input[0])
        output_url = output.get("URL")
        expected_url = expected_output[0].get("URL")
        assert output_url == expected_url, "Output from Demisto didn't match the expected output\nExpected: {} \n " \
                                           "Got: {}".format(expected_url, output_url
                                                            )


class TestSTIX2ToDemisto:
    def test_stix2_to_demisto(self, mocker):
        from StixParser import stix2_to_demisto
        stix_input, expected_output = _get_stix()
        try:
            d_results = _get_results_from_demisto(stix_input, stix2_to_demisto, mocker)
            d_results = json.loads(d_results)
            assert isinstance(d_results, list)
        except ValueError:
            pytest.fail(
                "Couldn't parse output as JSON", pytrace=True
            )
        expected_output = expected_output[2]
        results_length = len(expected_output)
        result_counter = 0
        for result in expected_output:
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


class TestHelperFunctions:
    err_msg = "Expected output [{}] but got [{}]"

    def test_ip_parser(self):
        from StixParser import ip_parser
        ip = "IP-1-2-3-4"
        expected_ip = "1.2.3.4"
        result = ip_parser(ip)
        assert result == expected_ip, self.err_msg.format(expected_ip, result)

    def test_ip_parser_not_ip(self):
        from StixParser import ip_parser
        not_ip = "trololololo"
        expected_value = not_ip
        result = ip_parser(expected_value)
        assert result == expected_value, self.err_msg.format(expected_value, result)

    def test_convert_to_json(self):
        from StixParser import convert_to_json
        js = "[]"
        expected = []
        result = convert_to_json(js)
        assert result == expected, self.err_msg.format(expected, result)

    def test_convert_to_json_false(self):
        from StixParser import convert_to_json
        js = "notjsonable"
        expected = None
        result = convert_to_json(js)
        assert result == expected, self.err_msg.format(expected, result)

    def test_create_timestamp(self):
        from StixParser import create_timestamp
        timestamp = "2019-05-28T16:38:17.845Z"
        result = create_timestamp(timestamp)
        assert timestamp == result, self.err_msg.format(timestamp, result)

    def test_create_timstamp_false(self):
        from StixParser import create_timestamp
        false_value = "nottimestamp"
        result = create_timestamp(false_value)
        assert result is None, self.err_msg.format(None, result)

    def test_create_indicator_entry(self):
        from StixParser import create_indicator_entry
        expected = {
            'indicator_type': 'ip',
            'value': '8.8.8.8',
            'CustomFields': {
                'indicatorId': 'ind_id',
                'stixPackageId': 'pkg_id'
            },
            'source': 'stix2',
            'score': 0,
            'timestamp': None
        }
        result = create_indicator_entry(
            "ip",
            "8.8.8.8",
            "pkg_id",
            "ind_id",
            None,
            "stix2",
            0
        )
        assert result == expected, self.err_msg.format(expected, result)

    def test_get_score(self):
        from StixParser import get_score
        score_field = "IMPACT:Low, This IP address is not used " \
                      "for legitimate hosting so there should be no operational impact.\n\n"
        result = get_score(score_field)
        assert result == 2, self.err_msg.format(result, 2)

    def test_get_score_false(self):
        from StixParser import get_score
        result = get_score("not a real score")
        assert result == 0, self.err_msg.format(0, result)


class TestStix1:
    @staticmethod
    def _get_results_from_file_path(file_path):
        entry_results_path = file_path.replace(".xml", "-results.json")
        with open(entry_results_path) as f:
            return json.load(f)

    @staticmethod
    def _get_results_from_demisto():
        res = demisto.results.call_args[0][0]
        return json.loads(res)

    @staticmethod
    def mock_demisto_with_file(file_path, mocker):
        with open(file_path) as f:
            file_string = f.read()
        mocker.patch.object(demisto, "args", return_value={"iocXml": file_string})

    def _run_on_files(self, files_path, func, mocker):
        err = "Got wrong results for path [{}]"
        files_list = get_files_in_dir(files_path, only_with_ext=".xml")
        for entry in files_list:
            self.mock_demisto_with_file(
                files_path + entry, mocker)
            func()
            demisto_results = self._get_results_from_demisto()
            expected_results = self._get_results_from_file_path(files_path + entry)
            assert expected_results == demisto_results, err.format(entry)

    def test_main(self, mocker):
        from StixParser import main
        files_path = "./TestData/stix1/"
        mock_demisto(mocker)
        self._run_on_files(files_path, main, mocker)
