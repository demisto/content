import pytest
from Feed_DHS import *


def compare(object_a, object_b):
    if isinstance(object_a, List):
        return compare_list(object_a, object_b)
    elif isinstance(object_a, Dict):
        return compare_dict(object_a, object_b)
    else:
        return object_a == object_b


def compare_list(list_a, list_b):
    try:
        list_a = list(sorted(list_a))
        list_b = list(sorted(list_b))
    except TypeError:
        pass
    for i in range(len(list_a)):
        if not compare(list_a[i], list_b[i]):
            return False
    return True


def compare_dict(dict_a, dict_b):
    keys = dict_a.keys()
    if not compare_list(keys, dict_b.keys()):
        return False
    for key in keys:
        if not compare(dict_a[key], dict_b[key]):
            return False
    return True


class TestTempFile:
    def test_create_file(self):
        data = 'test'
        temp_file = TempFile(data)
        with open(temp_file.path, 'r') as _file:
            assert _file.read() == data, 'temp file content failed'

    def test_removing_file(self):
        temp_file_name = TempFile('test').path
        assert not os.path.isfile(temp_file_name), 'file was not removed at the ens of live of the TempFile objet.'

    @pytest.mark.parametrize('suffix', ['test', 'py', 'pem', 'crt'])
    def test_suffix(self, suffix):
        temp_file_name = TempFile('test', suffix=suffix).path
        assert temp_file_name.endswith(suffix), 'file suffix dos not working as expected'


class TestHelpers:
    data_test_fix_rsa_data = [
        ('./test_data/rsa/test_fix_rsa_data.txt', 4),
        ('./test_data/rsa/test_fix_rsa_data2.txt', 2),
    ]

    @pytest.mark.parametrize('path, count', data_test_fix_rsa_data)
    def test_fix_rsa_data(self, path, count):
        with open(path, 'r') as _file:
            data = _file.read()
        demisto_data = data.replace('\n', ' ')
        fixed_data = fix_rsa_data(demisto_data, count)
        assert data == fixed_data, 'failed to parse the data from demisto params to RSA file'

    data_test_insert_id = [
        ('te{ID}st', 'tetestst'),
        ('{ID}', 'test'),
    ]

    @pytest.mark.parametrize('input_str, expected_output', data_test_insert_id)
    def test_insert_id(self, input_str, expected_output, mocker):
        mocker.patch.object(uuid, 'uuid4', return_value='test')
        output = insert_id(input_str)
        assert output == expected_output, 'failed to insert uuid'


class TestSafeDataGet:
    data_test_safe_data_get = [
        ('without_list', 'one_level_get'),
        (['standard_list', 'test'], 'multi_level_get')
    ]

    @pytest.mark.parametrize('get_list, expected_output', data_test_safe_data_get)
    def test_safe_data_get(self, get_list, expected_output):
        dict_data = {
            'without_list': 'one_level_get',
            'standard_list': {'test': 'multi_level_get'}
        }
        output = safe_data_get(dict_data, get_list)
        assert output == expected_output, 'failed to get the relevant data'

    def test_without_list(self):
        dict_data = {'without_list': 'one_level_get'}
        output = safe_data_get(dict_data, 'without_list')
        assert output == 'one_level_get'

    def test_with_list(self):
        dict_data = {'standard_list': {'test': 'multi_level_get'}}
        output = safe_data_get(dict_data, ['standard_list', 'test'])
        assert output == 'multi_level_get'

    def test_one_level_with_prefix(self):
        dict_data = {'TEST:without_list': 'one_level_get'}
        output = safe_data_get(dict_data, 'without_list', prefix='TEST')
        assert output == 'one_level_get'

    def test_multi_level_with_prefix(self):
        dict_data = {'TEST:standard_list': {'TEST:test': 'multi_level_get'}}
        output = safe_data_get(dict_data, ['standard_list', 'test'], prefix='TEST')
        assert output == 'multi_level_get'

    data_test_get_none_existing_path_with_prefix = [
        (
            {'TEST:standard_list': {'TEST:test': 'multi_level_get'}},
            ['standard_list1', 'test']
        ),
        (
            {'TEST:standard_list': {'TEST:test': 'multi_level_get'}},
            ['standard_list', 'test1']
        ),
        (
            {'without_list': 'one_level_get'},
            'without_list1'
        ),
    ]

    @pytest.mark.parametrize('dict_data, path', data_test_get_none_existing_path_with_prefix)
    def test_get_none_existing_path_with_prefix(self, dict_data, path):
        output = safe_data_get(dict_data, path, prefix='TEST')
        assert output is None

    data_test_get_none_existing_path_with_prefix = [
        ({'standard_list': {'test': 'multi_level_get'}}, ['standard_list1', 'test']),
        ({'standard_list': {'test': 'multi_level_get'}}, ['standard_list', 'test1']),
        ({'without_list': 'one_level_get'}, 'without_list1'),
    ]

    @pytest.mark.parametrize('dict_data, path', data_test_get_none_existing_path_with_prefix)
    def test_get_none_existing_path_without_prefix(self, dict_data, path):
        output = safe_data_get(dict_data, path)
        assert output is None

    data_test_with_default_value = [
        ({}, 'test', 'test'),
        ({}, None, None),
        ({'test': None}, 'something', None),
        ({'something': 'nothing'}, 'something', 'something')

    ]

    @pytest.mark.parametrize('dict_data, default, expected_output', data_test_with_default_value)
    def test_with_default_value(self, dict_data, default, expected_output):
        output = safe_data_get(dict_data, 'test', default=default)
        assert output == expected_output


class TestSetList:
    data_test_without_duplicate = [[], [1, 2, 3, 4]]

    @pytest.mark.parametrize('input_list', data_test_without_duplicate)
    def test_append_without_duplicate(self, input_list):
        set_list = SetList()
        for element in input_list:
            set_list.append(element)
        assert set_list.list == input_list

    data_test_with_duplicate = [
        ([1, 1, 2, 2, 3, 4], [1, 2, 3, 4]),
        ([1.5, 1.5, 1.5, 1.5], [1.5])
    ]

    @pytest.mark.parametrize('input_list, expected_list', data_test_with_duplicate)
    def test_append_with_duplicate(self, input_list, expected_list):
        set_list = SetList()
        for element in input_list:
            set_list.append(element)
        assert set_list.list == expected_list

    @pytest.mark.parametrize('input_list', data_test_without_duplicate)
    def test_extend_without_duplicate(self, input_list):
        set_list = SetList()
        set_list.extend(input_list)
        assert set_list.list == input_list

    @pytest.mark.parametrize('input_list, expected_list', data_test_with_duplicate)
    def test_extend_with_duplicate(self, input_list, expected_list):
        set_list = SetList()
        set_list.extend(input_list)
        assert set_list.list == expected_list

    data_test_using_extract_without_duplicate = [
        (
            [{'test1': 'test'}, {'test2': 'test'}],
            lambda x: json.dumps(x)
        )
    ]

    @pytest.mark.parametrize('input_list, extract', data_test_using_extract_without_duplicate)
    def test_using_extract_without_duplicate(self, input_list, extract):
        set_list = SetList(extract)
        set_list.extend(input_list)
        assert set_list.list == input_list

    data_test_using_extract_with_duplicate = [
        (
            [{'test1': 'test'}, {'test2': 'test'}, {'test1': 'test'}],
            lambda x: json.dumps(x),
            [{'test1': 'test'}, {'test2': 'test'}]
        )
    ]

    @pytest.mark.parametrize('input_list, extract, expected_list', data_test_using_extract_with_duplicate)
    def test_extend_using_extract_with_duplicate(self, input_list, extract, expected_list):
        set_list = SetList(extract)
        set_list.extend(input_list)
        assert set_list.list == expected_list


class TestIndicators:

    @staticmethod
    def read_json(path):
        with open(path, 'r') as json_file:
            json_file = json_file.read()
        return json.loads(json_file)

    @staticmethod
    def get_stix_header(block):
        return block.get('stix:STIX_Header', {})

    File = 'File'
    IP = 'IP'
    Domain = 'Domain'
    URL = 'URL'
    Email = 'Email'

    data_types = [IP, Domain, URL, Email, File]

    @pytest.mark.parametrize('data_type', data_types)
    def test_data_to_blocks(self, data_type):
        data = self.read_json(f'./test_data/data_from_DHS/{data_type}_data.json')
        test_blocks = Indicators._blocks(data)
        blocks = self.read_json(f'./test_data/blocks/blocks_from_{data_type}_data.json')
        assert test_blocks == blocks

    @pytest.mark.parametrize('data_type', data_types)
    def test_blocks_to_indicators(self, data_type):
        blocks = self.read_json(f'./test_data/blocks/blocks_from_{data_type}_data.json')
        test_indicators = []
        for block in blocks:
            test_indicators.extend(list(Indicators._indicators(block)))
        indicators = self.read_json(f'./test_data/indicators/indicators_from_{data_type}_data.json')
        assert test_indicators == indicators

    @pytest.mark.parametrize('data_type', data_types)
    def test_indicators_to_indicator_data(self, data_type):
        indicators = self.read_json(f'./test_data/indicators/indicators_from_{data_type}_data.json')
        test_data_indicators = list(map(lambda x: Indicators._indicator_data(x, '', ''), indicators))
        data_indicators = self.read_json(f'./test_data/data_indicators/{data_type}_data_indicators.json')
        assert test_data_indicators == data_indicators

    @pytest.mark.parametrize('data_type', data_types)
    def test_indicators_to_context_indicators(self, data_type):
        indicators = self.read_json(f'./test_data/data_indicators/{data_type}_data_indicators.json')
        test_context_indicators = list(map(indicator_to_context, indicators))
        context_indicators = self.read_json(f'./test_data/context_indicators/context_from_{data_type}_data.json')
        assert test_context_indicators == context_indicators

    data_test_tlp_color_from_header = [
        (IP, ['WHITE', 'WHITE', 'WHITE']),
        (Domain, ['GREEN']),
        (URL, ['AMBER']),
        (Email, ['AMBER']),
        (File, ['GREEN', 'GREEN', 'GREEN'])
    ]

    @pytest.mark.parametrize('data_type, tlp_colors', data_test_tlp_color_from_header)
    def test_tlp_color_from_header(self, data_type, tlp_colors):
        blocks_headers = list(
            map(self.get_stix_header, self.read_json(f'./test_data/blocks/blocks_from_{data_type}_data.json')))
        test_tlp_colors = list(map(Indicators._tlp_color_from_header, blocks_headers))
        assert test_tlp_colors == tlp_colors

    data_test_source_from_header = [
        (IP, ['Infoblox Inc'] * 3),
        (File, ['Reversing Labs'] * 3)
    ]

    @pytest.mark.parametrize('data_type, sources', data_test_source_from_header)
    def test_source_from_header(self, data_type, sources):
        sources_headers = list(
            map(self.get_stix_header, self.read_json(f'./test_data/blocks/blocks_from_{data_type}_data.json')))
        test_sources = list(map(Indicators._source_from_header, sources_headers))
        assert test_sources == sources


class TestCommands:

    def setup(self):
        self.client = TaxiiClient('', '')

    def test_command_test_module(self, mocker):
        demisto_results = mocker.patch.object(demisto, 'results')
        discovery_request = mocker.patch.object(self.client, 'discovery_request')
        mocker.patch.object(self.client, '_request', return_value='<test> "test" </test>')
        command_test_module(self.client)
        demisto_results.assert_called_with('ok')
        assert discovery_request.call_count == 1
