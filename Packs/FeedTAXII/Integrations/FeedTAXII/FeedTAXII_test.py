import json
import pytest

from FeedTAXII import TAXIIClient, fetch_indicators_command

""" helper functions """


def get_files_in_dir(mypath, only_with_ext=None):
    from os import listdir
    from os.path import isfile, join
    files_list = [f for f in listdir(mypath) if isfile(join(mypath, f))]
    if only_with_ext:
        return [f for f in files_list if f.endswith(only_with_ext)]
    return files_list


class TestStixDecode:
    FILE_PATH = 'FeedTAXII_test/StixDecodeTest'

    def test_decode(self):
        """Test decode on all files"""
        from FeedTAXII import StixDecode
        xml_files_names = get_files_in_dir(self.FILE_PATH, 'xml')
        for xml_f_name in xml_files_names:
            file_path = f'{self.FILE_PATH}/{xml_f_name}'
            with open(file_path, 'r') as xml_f:
                stix_str = xml_f.read()
                res = StixDecode.decode(stix_str)
                res_path = f'{file_path.rstrip(".xml")}-result.json'
                with open(res_path, 'r') as res_f:
                    expected_res = json.load(res_f)
                    assert expected_res == list(res[1])


class TestUtilFunctions:
    multipliers = {
        'minute': 60,
        'hour': 3600,
        'day': 86400,
    }

    def test_interval_in_sec_1(self):
        """Empty"""
        from FeedTAXII import interval_in_sec
        assert interval_in_sec(None) is None

    def test_interval_in_sec_2(self):
        """Integer"""
        from FeedTAXII import interval_in_sec
        val = 25
        assert interval_in_sec(val) == val

    def test_interval_in_sec_3(self):
        """Str with len < 2"""
        from FeedTAXII import interval_in_sec
        val = '25'
        with pytest.raises(ValueError):
            interval_in_sec(val)

    def test_interval_in_sec_4(self):
        """Str with len > 2"""
        from FeedTAXII import interval_in_sec
        val = '25 minutes ok'
        with pytest.raises(ValueError):
            interval_in_sec(val)

    def test_interval_in_sec_5(self):
        """Invalid str with len == 2"""
        from FeedTAXII import interval_in_sec
        val = '25 minu'
        with pytest.raises(ValueError):
            interval_in_sec(val)

    def test_interval_in_sec_6(self):
        """Valid str"""
        from FeedTAXII import interval_in_sec
        # Minutes
        val = '25 minutes'
        assert interval_in_sec(val) == 25 * self.multipliers['minute']
        # Hours
        val = '30 hours'
        assert interval_in_sec(val) == 30 * self.multipliers['hour']
        # Days
        val = '40 hours'
        assert interval_in_sec(val) == 40 * self.multipliers['hour']


class TestCommands:
    def test_fetch_indicators(self, mocker):
        client = TAXIIClient(collection='a collection')
        with open('FeedTAXII_test/TestCommands/raw_indicators.json', 'r') as f:
            raw_indicators = json.load(f)
            mocker.patch.object(client, 'build_iterator', return_value=raw_indicators)
            res = fetch_indicators_command(client)
            with open('FeedTAXII_test/TestCommands/indicators_results.json') as exp_f:
                expected = json.load(exp_f)
                assert res == expected


def test_poll_collection(mocker):
    """
    Given:
        - A collection of indicators in STIX format.

    When:
        - fetch_indicators_command is running.

    Then:
        - Validate the indicator extract as expected.
    """
    import requests_mock
    from FeedTAXII import fetch_indicators_command
    client = TAXIIClient(collection='a collection', poll_service='http://example/taxii-data')

    with open('FeedTAXII_test/TestCommands/collection_example.xml', 'rb') as xml_f:
        stix_content = xml_f.read()

    with requests_mock.Mocker() as m:
        m.post('http://example/taxii-data', content=stix_content)
        res = fetch_indicators_command(client)

    with open('FeedTAXII_test/TestCommands/indicators_example.json') as json_f:
        expected_result = json.load(json_f)

    assert res == expected_result


@pytest.mark.parametrize('tags', (['title', 'description'], []))
def test_tags_parameter(mocker, tags):
    """
    Given:
    - tags parameters
    When:
    - Executing any command on feed
    Then:
    - Validate the tags supplied exists in the indicators
    """
    client = TAXIIClient(collection='a collection', feedTags=json.dumps(tags))
    with open('FeedTAXII_test/TestCommands/raw_indicators.json', 'r') as f:
        raw_indicators = json.load(f)
        mocker.patch.object(client, 'build_iterator', return_value=raw_indicators)
        res = fetch_indicators_command(client)
        assert tags == list(res[0]['fields'].keys())
