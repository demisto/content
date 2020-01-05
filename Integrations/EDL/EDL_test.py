"""Imports"""
# STD packages
import json
from socket import inet_aton

# 3rd party packages
import pytest


'''Tests'''
@pytest.mark.helper_commands
class TestHelperFunctions:
    @pytest.mark.list_to_str
    def test_list_to_str_1(self):
        """Test invalid"""
        from EDL import list_to_str
        with pytest.raises(AttributeError):
            invalid_list_value = 2
            list_to_str(invalid_list_value)

        with pytest.raises(AttributeError):
            invalid_list_value = {'invalid': 'invalid'}
            list_to_str(invalid_list_value)

    @pytest.mark.list_to_str
    def test_list_to_str_2(self):
        """Test empty"""
        from EDL import list_to_str
        assert list_to_str(None) == ''
        assert list_to_str([]) == ''
        assert list_to_str({}) == ''

    @pytest.mark.list_to_str
    def test_list_to_str_3(self):
        """Test non empty fields"""
        from EDL import list_to_str
        valid_list_value = [1, 2, 3, 4]
        assert list_to_str(valid_list_value) == '1,2,3,4'
        assert list_to_str(valid_list_value, '.') == '1.2.3.4'
        assert list_to_str(valid_list_value, map_func=lambda x: f'{x}a') == '1a,2a,3a,4a'

    @pytest.mark.get_params_port
    def test_get_params_port_1(self):
        """Test invalid"""
        from EDL import get_params_port
        params = {'longRunningPort': 'invalid'}
        with pytest.raises(ValueError):
            get_params_port(params)

    @pytest.mark.get_params_port
    def test_get_params_port_2(self):
        """Test empty"""
        from EDL import get_params_port
        params = {'longRunningPort': ''}
        with pytest.raises(ValueError):
            get_params_port(params)

    @pytest.mark.get_params_port
    def test_get_params_port_3(self):
        """Test valid"""
        from EDL import get_params_port
        params = {'longRunningPort': '80'}
        assert get_params_port(params) == 80

    @pytest.mark.refresh_value_cache
    def test_refresh_value_cache_1(self, mocker):
        """Test out_format=text"""
        import EDL as edl
        with open('EDL_test/TestHelperFunctions/demisto_iocs.json', 'r') as iocs_json_f:
            mocker.patch.object(edl, 'find_indicators_to_limit', return_value=json.loads(iocs_json_f.read()))
            edl_vals = edl.refresh_value_cache(indicator_query='', out_format='text')
            assert len(edl_vals) == 38
            for ip in edl_vals:
                assert inet_aton(ip)  # assert all lines are ips

    @pytest.mark.refresh_value_cache
    def test_refresh_value_cache_2(self, mocker):
        """Test out_format=json"""
        import EDL as edl
        with open('EDL_test/TestHelperFunctions/demisto_iocs.json', 'r') as iocs_json_f:
            iocs_json = json.loads(iocs_json_f.read())
            mocker.patch.object(edl, 'find_indicators_to_limit', return_value=iocs_json)
            edl_vals = edl.refresh_value_cache(indicator_query='', out_format='json')
            assert isinstance(edl_vals[0], str)
            edl_vals = json.loads(edl_vals[0])
            assert iocs_json == edl_vals

    @pytest.mark.refresh_value_cache
    def test_refresh_value_cache_3(self, mocker):
        """Test out_format=csv"""
        import EDL as edl
        with open('EDL_test/TestHelperFunctions/demisto_iocs.json', 'r') as iocs_json_f:
            iocs_json = json.loads(iocs_json_f.read())
            mocker.patch.object(edl, 'find_indicators_to_limit', return_value=iocs_json)
            edl_vals = edl.refresh_value_cache(indicator_query='', out_format='csv')
            with open('EDL_test/TestHelperFunctions/iocs_out_csv.json', 'r') as iocs_out_f:
                iocs_out_json = json.load(iocs_out_f)
                assert iocs_out_json == edl_vals
                assert len(edl_vals[0].split(',')) == 29
