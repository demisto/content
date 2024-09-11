import pytest
from DHS_Feed import *


def compare(object_a, object_b):
    if isinstance(object_a, List):
        return compare_list(object_a, object_b)
    elif isinstance(object_a, Dict):
        return compare_dict(object_a, object_b)
    else:
        return object_a == object_b


def compare_list(list_a, list_b):
    try:
        list_a = sorted(list_a)
        list_b = sorted(list_b)
    except TypeError:
        pass
    if len(list_a) != len(list_b):
        return False
    return all(compare(a_obj, b_obj) for a_obj, b_obj in zip(list_a, list_b))


def compare_dict(dict_a, dict_b):
    keys = dict_a.keys()
    if not compare_list(keys, dict_b.keys()):
        return False
    return all(compare(dict_a[key], dict_b[key]) for key in keys)


class TestTempFile:
    def test_create_file(self):
        data = 'test'
        temp_file = TempFile(data)
        with open(temp_file.path) as _file:
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
        ('test_data/rsa/test_fix_rsa_data.txt', 4),
        ('test_data/rsa/test_fix_rsa_data2.txt', 2),
    ]

    @pytest.mark.parametrize('path, count', data_test_fix_rsa_data)
    def test_fix_rsa_data(self, path, count):
        with open(path) as _file:
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

    data_test_ssl_files_checker = [
        ('test_data/rsa/2048b-rsa-example-keypair.pem', 'test_data/rsa/2048b-rsa-example-cert.pem')
    ]

    @pytest.mark.parametrize('input_key, input_public', data_test_ssl_files_checker)
    def test_ssl_files_checker(self, input_key, input_public):
        with open(input_key) as input_key, open(input_public) as input_public:
            ssl_files_checker(input_public.read(), input_key.read())

    @pytest.mark.parametrize('input_key, input_public', data_test_ssl_files_checker)
    def test_ssl_files_checker_with_invalid_files(self, input_key, input_public):
        with open(input_key) as input_key:
            input_key = input_key.read()
        with open(input_public) as input_public:
            input_public = input_public.read()
        with pytest.raises(ValueError):
            temp_input_public = input_public.split('\n')[:-6]
            temp_input_public.extend(input_public.split('\n')[-7:])
            ssl_files_checker('\n'.join(temp_input_public), input_key)

        with pytest.raises(ValueError):
            temp_input_private = input_key.split('\n')[:-6]
            temp_input_private.extend(input_key.split('\n')[-7:])
            ssl_files_checker(input_public, '\n'.join(temp_input_private))


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

    data_test_get_none_existing_path_with_prefix2 = [
        ({'standard_list': {'test': 'multi_level_get'}}, ['standard_list1', 'test']),
        ({'standard_list': {'test': 'multi_level_get'}}, ['standard_list', 'test1']),
        ({'without_list': 'one_level_get'}, 'without_list1'),
    ]

    @pytest.mark.parametrize('dict_data, path', data_test_get_none_existing_path_with_prefix2)
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


class TestIndicators:

    @staticmethod
    def read_json(path):
        with open(path) as json_file:
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
        data = self.read_json(f'test_data/data_from_DHS/{data_type}_data.json')
        test_blocks = Indicators._blocks(data)
        blocks = self.read_json(f'test_data/blocks/blocks_from_{data_type}_data.json')
        assert test_blocks == blocks

    @pytest.mark.parametrize('data_type', data_types)
    def test_blocks_to_indicators(self, data_type):
        blocks = self.read_json(f'test_data/blocks/blocks_from_{data_type}_data.json')
        test_indicators = []
        for block in blocks:
            test_indicators.extend(list(Indicators._indicators(block)))
        indicators = self.read_json(f'test_data/indicators/indicators_from_{data_type}_data.json')
        assert test_indicators == indicators

    @pytest.mark.parametrize('data_type', data_types)
    def test_indicators_to_indicator_data(self, data_type):
        indicators = self.read_json(f'test_data/indicators/indicators_from_{data_type}_data.json')
        test_data_indicators = [Indicators._indicator_data(x, 'source', 'color', ['tag']) for x in indicators]
        data_indicators = self.read_json(f'test_data/data_indicators/{data_type}_data_indicators.json')
        assert test_data_indicators == data_indicators

    @pytest.mark.parametrize('data_type', data_types)
    def test_indicators_to_context_indicators(self, data_type):
        indicators = self.read_json(f'test_data/data_indicators/{data_type}_data_indicators.json')
        test_context_indicators = list(map(indicator_to_context, indicators))
        context_indicators = self.read_json(f'test_data/context_indicators/context_from_{data_type}_data.json')
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
            map(self.get_stix_header, self.read_json(f'test_data/blocks/blocks_from_{data_type}_data.json')))
        test_tlp_colors = list(map(Indicators._tlp_color_from_header, blocks_headers))
        assert test_tlp_colors == tlp_colors

    data_test_source_from_header = [
        (IP, ['Infoblox Inc'] * 3),
        (File, ['Reversing Labs'] * 3)
    ]

    @pytest.mark.parametrize('data_type, sources', data_test_source_from_header)
    def test_source_from_header(self, data_type, sources):
        sources_headers = list(
            map(self.get_stix_header, self.read_json(f'test_data/blocks/blocks_from_{data_type}_data.json')))
        test_sources = list(map(Indicators._source_from_header, sources_headers))
        assert test_sources == sources


class TestCommandTestModule:

    def nothing(self, *args, **kwargs):
        return lambda: self.data

    def setup_class(self):
        self.client = TaxiiClient('', '', '')
        self.data = None
        self.ssl_files_checker = self.get_first_fetch = self.discovery_request = None

    def mock_data(self, mocker):
        self.ssl_files_checker = mocker.patch('DHS_Feed.ssl_files_checker', new=self.nothing)
        self.get_first_fetch = mocker.patch('DHS_Feed.get_first_fetch', new=self.nothing)
        self.discovery_request = mocker.patch.object(self.client, 'discovery_request', new_callable=self.nothing)

    def test_command_test_module(self, mocker):
        self.mock_data(mocker)
        self.data = {'taxii_11:Discovery_Response': {'taxii_11:Service_Instance': ['somthing']}}
        assert command_test_module(self.client, '', '', '') == 'ok'

    def test_command_test_module_with_invalid_credential(self, mocker):
        self.mock_data(mocker)
        self.data = {'taxii_11:Status_Message': {'@status_type': 'UNAUTHORIZED'}}

        with pytest.raises(DemistoException, match='invalid credential.'):
            command_test_module(self.client, '', '', '')

    def test_command_test_module_with_unknown_error(self, mocker):
        self.mock_data(mocker)
        self.data = {}

        with pytest.raises(DemistoException, match='unknown error.'):
            command_test_module(self.client, '', '', '')
