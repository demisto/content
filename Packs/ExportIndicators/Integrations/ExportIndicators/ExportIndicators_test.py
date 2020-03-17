"""Imports"""
import json
import pytest
import demistomock as demisto
from netaddr import IPAddress


IOC_RES_LEN = 38

'''Tests'''


@pytest.mark.helper_commands
class TestHelperFunctions:
    @pytest.mark.get_outbound_ioc_values
    def test_get_outbound_ioc_values_1(self, mocker):
        """Test on_demand"""
        from ExportIndicators import get_outbound_ioc_values
        with open('ExportIndicators_test/TestHelperFunctions/iocs_cache_values_text.json', 'r') as iocs_text_values_f:
            iocs_text_dict = json.loads(iocs_text_values_f.read())
            mocker.patch.object(demisto, 'getIntegrationContext', return_value={"last_output": iocs_text_dict})
            ioc_list = get_outbound_ioc_values(
                out_format='text',
                on_demand=True,
                limit=50,
                offset=0
            )
            for ioc_row in ioc_list:
                assert ioc_row in iocs_text_dict

    @pytest.mark.get_outbound_ioc_values
    def test_get_outbound_ioc_values_2(self, mocker):
        """Test update by not on_demand with no refresh"""
        import CommonServerPython as CSP
        mocker.patch.object(CSP, 'parse_date_range', return_value=(1578383899, 1578383899))
        import ExportIndicators as ei
        with open('ExportIndicators_test/TestHelperFunctions/iocs_cache_values_text.json', 'r') as iocs_text_values_f:
            iocs_text_dict = json.loads(iocs_text_values_f.read())
            mocker.patch.object(demisto, 'getIntegrationContext', return_value={"last_output": iocs_text_dict})
            mocker.patch.object(ei, 'refresh_outbound_context', return_value=iocs_text_dict)
            mocker.patch.object(demisto, 'getLastRun', return_value={'last_run': 1578383898000})
            ioc_list = ei.get_outbound_ioc_values(
                out_format='text',
                on_demand=False,
                limit=50,
                offset=0,
                cache_refresh_rate='1 minute'
            )
            for ioc_row in ioc_list:
                assert ioc_row in iocs_text_dict

    @pytest.mark.get_outbound_ioc_values
    def test_get_outbound_ioc_values_3(self, mocker):
        """Test update by not on_demand with refresh"""
        import CommonServerPython as CSP
        mocker.patch.object(CSP, 'parse_date_range', return_value=(1578383898, 1578383898))
        import ExportIndicators as ei
        with open('ExportIndicators_test/TestHelperFunctions/iocs_cache_values_text.json', 'r') as iocs_text_values_f:
            iocs_text_dict = json.loads(iocs_text_values_f.read())
            mocker.patch.object(demisto, 'getIntegrationContext', return_value={"last_output": iocs_text_dict})
            mocker.patch.object(ei, 'refresh_outbound_context', return_value=iocs_text_dict)
            mocker.patch.object(demisto, 'getLastRun', return_value={'last_run': 1578383898000})
            ioc_list = ei.get_outbound_ioc_values(
                out_format='text',
                on_demand=False,
                limit=50,
                offset=0,
                cache_refresh_rate='1 minute'
            )
            for ioc_row in ioc_list:
                assert ioc_row in iocs_text_dict

    @pytest.mark.get_outbound_ioc_values
    def test_get_outbound_ioc_values_4(self, mocker):
        """Test update by request params change - limit"""
        import CommonServerPython as CSP
        mocker.patch.object(CSP, 'parse_date_range', return_value=(1578383898, 1578383898))
        import ExportIndicators as ei
        with open('ExportIndicators_test/TestHelperFunctions/iocs_cache_values_text.json', 'r') as iocs_text_values_f:
            iocs_text_dict = json.loads(iocs_text_values_f.read())
            mocker.patch.object(demisto, 'getIntegrationContext', return_value={"last_output": iocs_text_dict,
                                                                                "last_limit": 1, "last_offset": 0,
                                                                                "last_query": "type:ip",
                                                                                "last_format": "text"})
            mocker.patch.object(ei, 'refresh_outbound_context', return_value=iocs_text_dict)
            mocker.patch.object(demisto, 'getLastRun', return_value={'last_run': 1578383898000})
            ioc_list = ei.get_outbound_ioc_values(
                out_format='text',
                indicator_query="type:ip",
                on_demand=False,
                limit=50,
                offset=0,
                cache_refresh_rate='1 minute'
            )
            for ioc_row in ioc_list:
                assert ioc_row in iocs_text_dict

    @pytest.mark.get_outbound_ioc_values
    def test_get_outbound_ioc_values_5(self, mocker):
        """Test update by request params change - offset"""
        import CommonServerPython as CSP
        mocker.patch.object(CSP, 'parse_date_range', return_value=(1578383898, 1578383898))
        import ExportIndicators as ei
        with open('ExportIndicators_test/TestHelperFunctions/iocs_cache_values_text.json', 'r') as iocs_text_values_f:
            iocs_text_dict = json.loads(iocs_text_values_f.read())
            mocker.patch.object(demisto, 'getIntegrationContext', return_value={"last_output": iocs_text_dict,
                                                                                "last_limit": 50, "last_offset": 1,
                                                                                "last_query": "type:ip",
                                                                                "last_format": "text"})
            mocker.patch.object(ei, 'refresh_outbound_context', return_value=iocs_text_dict)
            mocker.patch.object(demisto, 'getLastRun', return_value={'last_run': 1578383898000})
            ioc_list = ei.get_outbound_ioc_values(
                out_format='text',
                indicator_query="type:ip",
                on_demand=False,
                limit=50,
                offset=0,
                cache_refresh_rate='1 minute'
            )
            for ioc_row in ioc_list:
                assert ioc_row in iocs_text_dict

    @pytest.mark.get_outbound_ioc_values
    def test_get_outbound_ioc_values_6(self, mocker):
        """Test update by request params change - query"""
        import CommonServerPython as CSP
        mocker.patch.object(CSP, 'parse_date_range', return_value=(1578383898, 1578383898))
        import ExportIndicators as ei
        with open('ExportIndicators_test/TestHelperFunctions/iocs_cache_values_text.json', 'r') as iocs_text_values_f:
            iocs_text_dict = json.loads(iocs_text_values_f.read())
            mocker.patch.object(demisto, 'getIntegrationContext', return_value={"last_output": iocs_text_dict,
                                                                                "last_limit": 50, "last_offset": 0,
                                                                                "last_query": "type:URL",
                                                                                "last_format": "text"})
            mocker.patch.object(ei, 'refresh_outbound_context', return_value=iocs_text_dict)
            mocker.patch.object(demisto, 'getLastRun', return_value={'last_run': 1578383898000})
            ioc_list = ei.get_outbound_ioc_values(
                out_format='text',
                indicator_query="type:ip",
                on_demand=False,
                limit=50,
                offset=0,
                cache_refresh_rate='1 minute'
            )
            for ioc_row in ioc_list:
                assert ioc_row in iocs_text_dict

    @pytest.mark.list_to_str
    def test_list_to_str_1(self):
        """Test invalid"""
        from ExportIndicators import list_to_str
        with pytest.raises(AttributeError):
            invalid_list_value = 2
            list_to_str(invalid_list_value)

        with pytest.raises(AttributeError):
            invalid_list_value = {'invalid': 'invalid'}
            list_to_str(invalid_list_value)

    @pytest.mark.list_to_str
    def test_list_to_str_2(self):
        """Test empty"""
        from ExportIndicators import list_to_str
        assert list_to_str(None) == ''
        assert list_to_str([]) == ''
        assert list_to_str({}) == ''

    @pytest.mark.list_to_str
    def test_list_to_str_3(self):
        """Test non empty fields"""
        from ExportIndicators import list_to_str
        valid_list_value = [1, 2, 3, 4]
        assert list_to_str(valid_list_value) == '1,2,3,4'
        assert list_to_str(valid_list_value, '.') == '1.2.3.4'
        assert list_to_str(valid_list_value, map_func=lambda x: f'{x}a') == '1a,2a,3a,4a'

    @pytest.mark.get_params_port
    def test_get_params_port_1(self):
        """Test invalid"""
        from CommonServerPython import DemistoException
        from ExportIndicators import get_params_port
        params = {'longRunningPort': 'invalid'}
        with pytest.raises(DemistoException):
            get_params_port(params)

    @pytest.mark.get_params_port
    def test_get_params_port_2(self):
        """Test empty"""
        from ExportIndicators import get_params_port
        params = {'longRunningPort': ''}
        with pytest.raises(ValueError):
            get_params_port(params)

    @pytest.mark.get_params_port
    def test_get_params_port_3(self):
        """Test valid"""
        from ExportIndicators import get_params_port
        params = {'longRunningPort': '80'}
        assert get_params_port(params) == 80

    @pytest.mark.refresh_outbound_context
    def test_refresh_outbound_context_1(self, mocker):
        """Test out_format=text"""
        import ExportIndicators as ei
        with open('ExportIndicators_test/TestHelperFunctions/demisto_iocs.json', 'r') as iocs_json_f:
            iocs_json = json.loads(iocs_json_f.read())
            mocker.patch.object(ei, 'find_indicators_with_limit', return_value=iocs_json)
            ei_vals = ei.refresh_outbound_context(indicator_query='', out_format='text')
            for ioc in iocs_json:
                ip = ioc.get('value')
                assert ip in ei_vals

    @pytest.mark.refresh_outbound_context
    def test_refresh_outbound_context_2(self, mocker):
        """Test out_format=json"""
        import ExportIndicators as ei
        with open('ExportIndicators_test/TestHelperFunctions/demisto_iocs.json', 'r') as iocs_json_f:
            iocs_json = json.loads(iocs_json_f.read())
            mocker.patch.object(ei, 'find_indicators_with_limit', return_value=iocs_json)
            ei_vals = ei.refresh_outbound_context(indicator_query='', out_format='json')
            assert isinstance(ei_vals, str)
            ei_vals = json.loads(ei_vals)
            assert iocs_json == ei_vals

    @pytest.mark.refresh_outbound_context
    def test_refresh_outbound_context_3(self, mocker):
        """Test out_format=csv"""
        import ExportIndicators as ei
        with open('ExportIndicators_test/TestHelperFunctions/demisto_iocs.json', 'r') as iocs_json_f:
            iocs_json = json.loads(iocs_json_f.read())
            mocker.patch.object(ei, 'find_indicators_with_limit', return_value=iocs_json)
            ei_vals = ei.refresh_outbound_context(indicator_query='', out_format='csv')
            with open('ExportIndicators_test/TestHelperFunctions/iocs_out_csv.txt', 'r') as iocs_out_f:
                iocs_out = iocs_out_f.read()
                assert iocs_out == ei_vals

    @pytest.mark.refresh_outbound_context
    def test_refresh_outbound_context_4(self, mocker):
        """Test out_format=json-seq"""
        import ExportIndicators as ei
        with open('ExportIndicators_test/TestHelperFunctions/demisto_iocs.json', 'r') as iocs_json_f:
            iocs_json = json.loads(iocs_json_f.read())
            mocker.patch.object(ei, 'find_indicators_with_limit', return_value=iocs_json)
            ei_vals = ei.refresh_outbound_context(indicator_query='', out_format='json-seq')
            with open('ExportIndicators_test/TestHelperFunctions/iocs_out_json_seq.txt', 'r') as iocs_out_f:
                iocs_out = iocs_out_f.read()
                assert iocs_out == ei_vals

    @pytest.mark.find_indicators_with_limit
    def test_find_indicators_with_limit_1(self, mocker):
        """Test find indicators limit"""
        import ExportIndicators as ei
        with open('ExportIndicators_test/TestHelperFunctions/demisto_iocs.json', 'r') as iocs_json_f:
            iocs_json = json.loads(iocs_json_f.read())
            limit = 30
            mocker.patch.object(ei, 'find_indicators_with_limit_loop', return_value=(iocs_json, 1))
            ei_vals = ei.find_indicators_with_limit(indicator_query='', limit=limit, offset=0)
            assert len(ei_vals) == limit

    @pytest.mark.find_indicators_with_limit
    def test_find_indicators_with_limit_and_offset_1(self, mocker):
        """Test find indicators limit and offset"""
        import ExportIndicators as ei
        with open('ExportIndicators_test/TestHelperFunctions/demisto_iocs.json', 'r') as iocs_json_f:
            iocs_json = json.loads(iocs_json_f.read())
            limit = 30
            offset = 1
            mocker.patch.object(ei, 'find_indicators_with_limit_loop', return_value=(iocs_json, 1))
            ei_vals = ei.find_indicators_with_limit(indicator_query='', limit=limit, offset=offset)
            assert len(ei_vals) == limit
            # check that the first value is the second on the list
            assert ei_vals[0].get('value') == '212.115.110.19'

    @pytest.mark.find_indicators_with_limit_loop
    def test_find_indicators_with_limit_loop_1(self, mocker):
        """Test find indicators stops when reached last page"""
        import ExportIndicators as ei
        with open('ExportIndicators_test/TestHelperFunctions/demisto_iocs.json', 'r') as iocs_json_f:
            iocs_dict = {'iocs': json.loads(iocs_json_f.read())}
            limit = 50
            mocker.patch.object(demisto, 'searchIndicators', return_value=iocs_dict)
            ei_vals, nxt_pg = ei.find_indicators_with_limit_loop(indicator_query='', limit=limit)
            assert nxt_pg == 1  # assert entered into loop

    @pytest.mark.find_indicators_with_limit_loop
    def test_find_indicators_with_limit_loop_2(self, mocker):
        """Test find indicators stops when reached limit"""
        import ExportIndicators as ei
        with open('ExportIndicators_test/TestHelperFunctions/demisto_iocs.json', 'r') as iocs_json_f:
            iocs_dict = {'iocs': json.loads(iocs_json_f.read())}
            limit = 30
            mocker.patch.object(demisto, 'searchIndicators', return_value=iocs_dict)
            ei.PAGE_SIZE = IOC_RES_LEN
            ei_vals, nxt_pg = ei.find_indicators_with_limit_loop(indicator_query='', limit=limit,
                                                                 last_found_len=IOC_RES_LEN)
            assert nxt_pg == 1  # assert entered into loop

    @pytest.mark.create_values_for_returned_dict
    def test_create_values_for_returned_dict_1(self):
        """Test CSV out"""
        from ExportIndicators import create_values_for_returned_dict, FORMAT_CSV, DONT_COLLAPSE
        with open('ExportIndicators_test/TestHelperFunctions/demisto_iocs.json', 'r') as iocs_json_f:
            iocs_json = json.loads(iocs_json_f.read())
            csv_out, _ = create_values_for_returned_dict(iocs_json, FORMAT_CSV, DONT_COLLAPSE)
            # assert len(csv_out) == IOC_RES_LEN + 1
            with open('ExportIndicators_test/TestHelperFunctions/iocs_out_csv.txt', 'r') as iocs_out_f:
                expected_csv_out = iocs_out_f.read()
                for csv_line in csv_out.values():
                    assert csv_line in expected_csv_out

    @pytest.mark.create_values_for_returned_dict
    def test_create_values_for_returned_dict_2(self):
        """Test JSON out"""
        from ExportIndicators import create_values_for_returned_dict, FORMAT_JSON, CTX_VALUES_KEY
        with open('ExportIndicators_test/TestHelperFunctions/demisto_iocs.json', 'r') as iocs_json_f:
            iocs_json = json.load(iocs_json_f)
            result_dict, _ = create_values_for_returned_dict(iocs_json, FORMAT_JSON)
            json_out = json.loads(result_dict.get(CTX_VALUES_KEY))
            assert json_out == iocs_json

    @pytest.mark.create_values_for_returned_dict
    def test_create_values_for_returned_dict_3(self):
        """Test JSON_SEQ out"""
        from ExportIndicators import create_values_for_returned_dict, FORMAT_JSON_SEQ, CTX_VALUES_KEY
        with open('ExportIndicators_test/TestHelperFunctions/demisto_iocs.json', 'r') as iocs_json_f:
            iocs_json = json.loads(iocs_json_f.read())
            result_dict, _ = create_values_for_returned_dict(iocs_json, FORMAT_JSON_SEQ)
            json_seq_out = result_dict.get(CTX_VALUES_KEY)
            for seq_line in json_seq_out.split('\n'):
                assert json.loads(seq_line) in iocs_json

    @pytest.mark.create_values_for_returned_dict
    def test_create_values_for_returned_dict_4(self):
        """Test TEXT out"""
        from ExportIndicators import create_values_for_returned_dict, FORMAT_TEXT, CTX_VALUES_KEY
        with open('ExportIndicators_test/TestHelperFunctions/demisto_iocs.json', 'r') as iocs_json_f:
            iocs_json = json.loads(iocs_json_f.read())
            result_dict, _ = create_values_for_returned_dict(iocs_json, FORMAT_TEXT)
            text_out = result_dict.get(CTX_VALUES_KEY)
            with open('ExportIndicators_test/TestHelperFunctions/iocs_cache_values_text.json', 'r') as iocs_txt_f:
                iocs_txt_json = json.load(iocs_txt_f)
                for line in text_out.split('\n'):
                    assert line in iocs_txt_json

    @pytest.mark.validate_basic_authentication
    def test_validate_basic_authentication(self):
        """Test Authentication"""
        from ExportIndicators import validate_basic_authentication
        username, password = 'user', 'pwd'
        data = {
            "empty_auth": {},
            "basic_missing_auth": {
                "Authorization": "missing basic"
            },
            "colon_missing_auth": {
                "Authorization": "Basic bWlzc2luZ19jb2xvbg=="
            },
            "wrong_length_auth": {
                "Authorization": "Basic YTpiOmM="
            },
            "wrong_credentials_auth": {
                "Authorization": "Basic YTpi"
            },
            "right_credentials_auth": {
                "Authorization": "Basic dXNlcjpwd2Q="
            }
        }
        assert not validate_basic_authentication(data.get('empty_auth'), username, password)
        assert not validate_basic_authentication(data.get('basic_missing_auth'), username, password)
        assert not validate_basic_authentication(data.get('colon_missing_auth'), username, password)
        assert not validate_basic_authentication(data.get('wrong_length_auth'), username, password)
        assert not validate_basic_authentication(data.get('wrong_credentials_auth'), username, password)
        assert validate_basic_authentication(data.get('right_credentials_auth'), username, password)

    @pytest.mark.ips_to_ranges
    def test_ips_to_ranges_range(self):
        from ExportIndicators import ips_to_ranges, COLLAPSE_TO_RANGES
        ip_list = [IPAddress("1.1.1.1"), IPAddress("25.24.23.22"), IPAddress("22.21.20.19"),
                   IPAddress("1.1.1.2"), IPAddress("1.2.3.4"), IPAddress("1.1.1.3"), IPAddress("2.2.2.2"),
                   IPAddress("1.2.3.5")]

        ip_range_list = ips_to_ranges(ip_list, COLLAPSE_TO_RANGES)
        assert "1.1.1.1-1.1.1.3" in ip_range_list
        assert "1.2.3.4-1.2.3.5" in ip_range_list
        assert "1.1.1.2" not in ip_range_list
        assert "2.2.2.2" in ip_range_list

    @pytest.mark.ips_to_cidrs
    def test_ips_to_ranges_cidr(self):
        from ExportIndicators import ips_to_ranges, COLLAPSE_TO_CIDR
        ip_list = [IPAddress("1.1.1.1"), IPAddress("25.24.23.22"), IPAddress("22.21.20.19"),
                   IPAddress("1.1.1.2"), IPAddress("1.2.3.4"), IPAddress("1.1.1.3"), IPAddress("2.2.2.2"),
                   IPAddress("1.2.3.5")]

        ip_range_list = ips_to_ranges(ip_list, COLLAPSE_TO_CIDR)
        assert "1.1.1.1" in ip_range_list
        assert "1.1.1.2/31" in ip_range_list
        assert "1.2.3.4/31" in ip_range_list
        assert "1.2.3.5" not in ip_range_list
        assert "1.1.1.3" not in ip_range_list
        assert "2.2.2.2" in ip_range_list
