"""Imports"""
import json
import pytest
import demistomock as demisto
from netaddr import IPAddress

IOC_RES_LEN = 38

'''Tests'''


@pytest.mark.helper_commands
class TestHelperFunctions:
    @pytest.mark.get_edl_ioc_values
    def test_get_edl_ioc_values_1(self, mocker):
        """Test on_demand"""
        from EDL import get_edl_ioc_values, RequestArguments
        with open('EDL_test/TestHelperFunctions/iocs_cache_values_text.json', 'r') as iocs_text_values_f:
            iocs_text_dict = json.loads(iocs_text_values_f.read())
            integration_context = {"last_output": iocs_text_dict}
            request_args = RequestArguments(query='', limit=50, offset=0)
            ioc_list = get_edl_ioc_values(
                on_demand=True,
                request_args=request_args,
                integration_context=integration_context
            )
            for ioc_row in ioc_list:
                assert ioc_row in iocs_text_dict

    @pytest.mark.get_edl_ioc_values
    def test_get_edl_ioc_values_2(self, mocker):
        """Test update by not on_demand with no refresh"""
        import CommonServerPython as CSP
        mocker.patch.object(CSP, 'parse_date_range', return_value=(1578383899, 1578383899))
        import EDL as edl
        with open('EDL_test/TestHelperFunctions/iocs_cache_values_text.json', 'r') as iocs_text_values_f:
            iocs_text_dict = json.loads(iocs_text_values_f.read())
            mocker.patch.object(edl, 'refresh_edl_context', return_value=iocs_text_dict)
            mocker.patch.object(demisto, 'getLastRun', return_value={'last_run': 1578383898000})
            request_args = edl.RequestArguments(query='', limit=50, offset=0)
            ioc_list = edl.get_edl_ioc_values(
                on_demand=False,
                request_args=request_args,
                integration_context=iocs_text_dict,
                cache_refresh_rate='1 minute'
            )
            for ioc_row in ioc_list:
                assert ioc_row in iocs_text_dict

    @pytest.mark.get_edl_ioc_values
    def test_get_edl_ioc_values_3(self, mocker):
        """Test update by not on_demand with refresh"""
        import CommonServerPython as CSP
        mocker.patch.object(CSP, 'parse_date_range', return_value=(1578383898, 1578383898))
        import EDL as edl
        with open('EDL_test/TestHelperFunctions/iocs_cache_values_text.json', 'r') as iocs_text_values_f:
            iocs_text_dict = json.loads(iocs_text_values_f.read())
            mocker.patch.object(demisto, 'getIntegrationContext', return_value=iocs_text_dict)
            request_args = edl.RequestArguments(query='', limit=50, offset=0)
            mocker.patch.object(demisto, 'getLastRun', return_value={'last_run': 1578383898000})
            ioc_list = edl.get_edl_ioc_values(
                on_demand=False,
                request_args=request_args,
                integration_context=iocs_text_dict,
                cache_refresh_rate='1 minute'
            )
            for ioc_row in ioc_list:
                assert ioc_row in iocs_text_dict

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
        from CommonServerPython import DemistoException
        from EDL import get_params_port
        params = {'longRunningPort': 'invalid'}
        with pytest.raises(DemistoException):
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

    @pytest.mark.refresh_edl_context
    def test_refresh_edl_context_1(self, mocker):
        """Sanity"""
        import EDL as edl
        with open('EDL_test/TestHelperFunctions/demisto_iocs.json', 'r') as iocs_json_f:
            iocs_json = json.loads(iocs_json_f.read())
            mocker.patch.object(edl, 'find_indicators_to_limit', return_value=iocs_json)
            request_args = edl.RequestArguments(query='', limit=38, url_port_stripping=True)
            edl_vals = edl.refresh_edl_context(request_args)
            for ioc in iocs_json:
                ip = ioc.get('value')
                stripped_ip = edl._PORT_REMOVAL.sub(edl._URL_WITHOUT_PORT, ip)
                if stripped_ip != ip:
                    assert stripped_ip.replace('https://', '') in edl_vals
                else:
                    assert ip in edl_vals

    @pytest.mark.find_indicators_to_limit
    def test_find_indicators_to_limit_1(self, mocker):
        """Test find indicators limit"""
        import EDL as edl
        with open('EDL_test/TestHelperFunctions/demisto_iocs.json', 'r') as iocs_json_f:
            iocs_json = json.loads(iocs_json_f.read())
            limit = 30
            mocker.patch.object(edl, 'find_indicators_to_limit_loop', return_value=(iocs_json, 1))
            edl_vals = edl.find_indicators_to_limit(indicator_query='', limit=limit)
            assert len(edl_vals) == limit

    @pytest.mark.find_indicators_to_limit
    def test_find_indicators_to_limit_and_offset_1(self, mocker):
        """Test find indicators limit and offset"""
        import EDL as edl
        with open('EDL_test/TestHelperFunctions/demisto_iocs.json', 'r') as iocs_json_f:
            iocs_json = json.loads(iocs_json_f.read())
            limit = 30
            offset = 1
            mocker.patch.object(edl, 'find_indicators_to_limit_loop', return_value=(iocs_json, 1))
            edl_vals = edl.find_indicators_to_limit(indicator_query='', limit=limit, offset=offset)
            assert len(edl_vals) == limit
            # check that the first value is the second on the list
            assert edl_vals[0].get('value') == '212.115.110.19'

    @pytest.mark.find_indicators_to_limit_loop
    def test_find_indicators_to_limit_loop_1(self, mocker):
        """Test find indicators stops when reached last page"""
        import EDL as edl
        with open('EDL_test/TestHelperFunctions/demisto_iocs.json', 'r') as iocs_json_f:
            iocs_dict = {'iocs': json.loads(iocs_json_f.read())}
            limit = 50
            mocker.patch.object(demisto, 'searchIndicators', return_value=iocs_dict)
            edl_vals, nxt_pg = edl.find_indicators_to_limit_loop(indicator_query='', limit=limit)
            assert nxt_pg == 1  # assert entered into loop

    @pytest.mark.find_indicators_to_limit_loop
    def test_find_indicators_to_limit_loop_2(self, mocker):
        """Test find indicators stops when reached limit"""
        import EDL as edl
        with open('EDL_test/TestHelperFunctions/demisto_iocs.json', 'r') as iocs_json_f:
            iocs_dict = {'iocs': json.loads(iocs_json_f.read())}
            limit = 30
            mocker.patch.object(demisto, 'searchIndicators', return_value=iocs_dict)
            edl.PAGE_SIZE = IOC_RES_LEN
            edl_vals, nxt_pg = edl.find_indicators_to_limit_loop(indicator_query='', limit=limit,
                                                                 last_found_len=IOC_RES_LEN)
            assert nxt_pg == 1  # assert entered into loop

    @pytest.mark.validate_basic_authentication
    def test_create_values_for_returned_dict(self):
        from EDL import create_values_for_returned_dict, EDL_VALUES_KEY, RequestArguments
        with open('EDL_test/TestHelperFunctions/demisto_url_iocs.json', 'r') as iocs_json_f:
            iocs_json = json.loads(iocs_json_f.read())

            # strips port numbers
            request_args = RequestArguments(query='', drop_invalids=True, url_port_stripping=True)
            returned_dict, num_of_indicators = create_values_for_returned_dict(iocs_json, request_args)
            returned_output = returned_dict.get(EDL_VALUES_KEY)
            assert returned_output == "1.2.3.4/wget\nwww.demisto.com/cool"
            assert num_of_indicators == 2

            # should ignore indicators with port numbers
            request_args = RequestArguments(query='', drop_invalids=True, url_port_stripping=False)
            returned_dict, num_of_indicators = create_values_for_returned_dict(iocs_json, request_args)
            returned_output = returned_dict.get(EDL_VALUES_KEY)
            assert returned_output == 'www.demisto.com/cool'
            assert num_of_indicators == 1

            # should not ignore indicators with '*' in them
            request_args = RequestArguments(query='', drop_invalids=False, url_port_stripping=False)
            returned_dict, num_of_indicators = create_values_for_returned_dict(iocs_json, request_args)
            returned_output = returned_dict.get(EDL_VALUES_KEY)
            assert returned_output == 'www.demisto.com/cool\nwww.demisto.com/*'
            assert num_of_indicators == 2

    @pytest.mark.validate_basic_authentication
    def test_validate_basic_authentication(self):
        """Test Authentication"""
        from EDL import validate_basic_authentication
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
        username, password = 'user', 'pwd'
        assert not validate_basic_authentication(data.get('empty_auth'), username, password)
        assert not validate_basic_authentication(data.get('basic_missing_auth'), username, password)
        assert not validate_basic_authentication(data.get('colon_missing_auth'), username, password)
        assert not validate_basic_authentication(data.get('wrong_length_auth'), username, password)
        assert not validate_basic_authentication(data.get('wrong_credentials_auth'), username, password)
        assert validate_basic_authentication(data.get('right_credentials_auth'), username, password)

    @pytest.mark.ips_to_ranges
    def test_ips_to_ranges_range(self):
        from EDL import ips_to_ranges, COLLAPSE_TO_RANGES
        ip_list = [IPAddress("1.1.1.1"), IPAddress("25.24.23.22"), IPAddress("22.21.20.19"),
                   IPAddress("1.1.1.2"), IPAddress("1.2.3.4"), IPAddress("1.1.1.3"), IPAddress("2.2.2.2"),
                   IPAddress("1.2.3.5")]

        ip_range_list = ips_to_ranges(ip_list, COLLAPSE_TO_RANGES)
        assert "1.1.1.1-1.1.1.3" in ip_range_list
        assert "1.2.3.4-1.2.3.5" in ip_range_list
        assert "1.1.1.2" not in ip_range_list
        assert "2.2.2.2" in ip_range_list
        assert "25.24.23.22" in ip_range_list

    @pytest.mark.ips_to_cidrs
    def test_ips_to_ranges_cidr(self):
        from EDL import ips_to_ranges, COLLAPSE_TO_CIDR
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
        assert "25.24.23.22" in ip_range_list
