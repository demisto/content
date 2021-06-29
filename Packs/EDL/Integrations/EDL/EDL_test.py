"""Imports"""
import json
import pytest
import os
from netaddr import IPAddress
from tempfile import mkdtemp

IOC_RES_LEN = 38

'''Tests'''


class TestRequestArguments:
    from EDL import RequestArguments
    context_json = {
        RequestArguments.CTX_QUERY_KEY: "query",
        RequestArguments.CTX_LIMIT_KEY: 10,
        RequestArguments.CTX_OFFSET_KEY: 1,
        RequestArguments.CTX_INVALIDS_KEY: True,
        RequestArguments.CTX_PORT_STRIP_KEY: True,
        RequestArguments.CTX_COLLAPSE_IPS_KEY: "collapse",
        RequestArguments.CTX_INVALIDATE_EDL_KEY: True,
        RequestArguments.CTX_DOMAIN_GLOB_KEY: True
    }

    request_args = RequestArguments(
        query=context_json[RequestArguments.CTX_QUERY_KEY],
        limit=context_json[RequestArguments.CTX_LIMIT_KEY],
        offset=context_json[RequestArguments.CTX_OFFSET_KEY],
        url_port_stripping=context_json[RequestArguments.CTX_PORT_STRIP_KEY],
        drop_invalids=context_json[RequestArguments.CTX_PORT_STRIP_KEY],
        collapse_ips=context_json[RequestArguments.CTX_COLLAPSE_IPS_KEY],
        invalidate_empty_edl=context_json[RequestArguments.CTX_INVALIDATE_EDL_KEY],
        dont_duplicate_glob=context_json[RequestArguments.CTX_DOMAIN_GLOB_KEY])

    def test_to_context_json(self):
        """
        Test to_context_json transforms the class to the expected context_json
        Given:
            -  request_args
        When:
            - calling to_context_json()
        Then:
            - creates a dict in the expected format
        """
        assert self.request_args.to_context_json() == self.context_json

    def test_from_context_json(self):
        """
        Test from_context_json creates an instance of the class with all the values
        Given:
            - context json with data
        When:
            - calling from_context_json()
        Then:
            - creates an instance of RequestArguments with the proper values
        """
        actual_request_args_dict = self.RequestArguments.from_context_json(self.context_json).__dict__
        expected_request_args_dict = self.request_args.__dict__
        for key, val in actual_request_args_dict.items():
            assert expected_request_args_dict[key] == val


class TestHelperFunctions:
    def test_get_edl_on_demand__with_cache(self, mocker):
        """
        Test get_edl_on_demand fetches indicators from cache
        Given:
            - No refresh signal in context
            - Cache has a valid value
        When:
            - calling get_edl_on_demand
        Then:
            - return the edl from the system file
        """
        import EDL as edl
        edl.EDL_ON_DEMAND_CACHE_PATH = 'EDL_test/TestHelperFunctions/iocs_cache_values_text.txt'
        mocker.patch.object(edl, 'get_integration_context', return_value={})
        actual_edl = edl.get_edl_on_demand()
        with open(edl.EDL_ON_DEMAND_CACHE_PATH, 'r') as f:
            expected_edl = f.read()
            assert actual_edl == expected_edl

    def test_get_edl_on_demand__with_refresh_signal(self, mocker):
        """
        Test get_edl_on_demand fetches new indicators and stores them to cache when key is passed
        Given:
            - refresh signal in context
        When:
            - calling get_edl_on_demand
        Then:
            - save the edl to the system file
        """
        import EDL as edl
        expected_edl = "8.8.8.8"
        ctx = {edl.EDL_ON_DEMAND_KEY: True, edl.RequestArguments.CTX_QUERY_KEY: "*"}
        tmp_dir = mkdtemp()
        edl.EDL_ON_DEMAND_CACHE_PATH = os.path.join(tmp_dir, 'cache')
        mocker.patch.object(edl, 'get_integration_context', return_value=ctx)
        mocker.patch.object(edl, 'create_new_edl', return_value=expected_edl)
        actual_edl = edl.get_edl_on_demand()
        with open(edl.EDL_ON_DEMAND_CACHE_PATH, 'r') as f:
            cached_edl = f.read()
            assert actual_edl == expected_edl == cached_edl

    def test_list_to_str_1(self):
        """Test invalid"""
        from EDL import list_to_str
        with pytest.raises(AttributeError):
            invalid_list_value = 2
            list_to_str(invalid_list_value)

        with pytest.raises(AttributeError):
            invalid_list_value = {'invalid': 'invalid'}
            list_to_str(invalid_list_value)

    def test_list_to_str_2(self):
        """Test empty"""
        from EDL import list_to_str
        assert list_to_str(None) == ''
        assert list_to_str([]) == ''
        assert list_to_str({}) == ''

    def test_list_to_str_3(self):
        """Test non empty fields"""
        from EDL import list_to_str
        valid_list_value = [1, 2, 3, 4]
        assert list_to_str(valid_list_value) == '1,2,3,4'
        assert list_to_str(valid_list_value, '.') == '1.2.3.4'
        assert list_to_str(valid_list_value, map_func=lambda x: f'{x}a') == '1a,2a,3a,4a'

    def test_get_params_port_1(self):
        """Test invalid"""
        from CommonServerPython import DemistoException
        from EDL import get_params_port
        params = {'longRunningPort': 'invalid'}
        with pytest.raises(DemistoException):
            get_params_port(params)

    def test_get_params_port_2(self):
        """Test empty"""
        from EDL import get_params_port
        params = {'longRunningPort': ''}
        with pytest.raises(ValueError):
            get_params_port(params)

    def test_get_params_port_3(self):
        """Test valid"""
        from EDL import get_params_port
        params = {'longRunningPort': '80'}
        assert get_params_port(params) == 80

    def test_create_new_edl_1(self, mocker):
        """Sanity"""
        import EDL as edl
        with open('EDL_test/TestHelperFunctions/demisto_iocs.json', 'r') as iocs_json_f:
            iocs_json = json.loads(iocs_json_f.read())
            mocker.patch.object(edl, 'find_indicators_to_limit', return_value=iocs_json)
            request_args = edl.RequestArguments(query='', limit=38, url_port_stripping=True)
            edl_vals = edl.create_new_edl(request_args)
            for ioc in iocs_json:
                ip = ioc.get('value')
                stripped_ip = edl._PORT_REMOVAL.sub(edl._URL_WITHOUT_PORT, ip)
                if stripped_ip != ip:
                    assert stripped_ip.replace('https://', '') in edl_vals
                else:
                    assert ip in edl_vals

    def test_find_indicators_to_limit(self, mocker):
        """Test find indicators limit"""
        import EDL as edl
        with open('EDL_test/TestHelperFunctions/demisto_iocs.json', 'r') as iocs_json_f:
            iocs_json = json.loads(iocs_json_f.read())
            indicator_searcher_res = [{'iocs': iocs_json}, {'iocs': []}]
            limit = 37
            indicator_searcher = edl.IndicatorsSearcher()
            mocker.patch.object(indicator_searcher, 'search_indicators_by_version', side_effect=indicator_searcher_res)
            edl_vals = edl.find_indicators_to_limit(indicator_searcher=indicator_searcher,
                                                    indicator_query='',
                                                    limit=limit)
            assert len(edl_vals) == limit

    def test_format_indicators(self):
        from EDL import format_indicators, RequestArguments
        with open('EDL_test/TestHelperFunctions/demisto_url_iocs.json', 'r') as iocs_json_f:
            iocs_json = json.loads(iocs_json_f.read())

            # strips port numbers
            request_args = RequestArguments(query='', drop_invalids=True, url_port_stripping=True)
            returned_output = format_indicators(iocs_json, request_args)
            assert returned_output == ['1.2.3.4/wget', 'www.demisto.com/cool']

            # should ignore indicators with port numbers
            request_args = RequestArguments(query='', drop_invalids=True, url_port_stripping=False)
            returned_output = format_indicators(iocs_json, request_args)
            assert returned_output == ['www.demisto.com/cool']

            # should not ignore indicators with '*' in them
            request_args = RequestArguments(query='', drop_invalids=False, url_port_stripping=False)
            returned_output = format_indicators(iocs_json, request_args)
            assert returned_output == ['www.demisto.com/cool', 'www.demisto.com/*']

    def test_format_indicators__filters(self):
        from EDL import format_indicators, RequestArguments
        iocs = [
            {'value': '2603:1006:1400::/40', 'indicator_type': 'IPv6'},
            {'value': '2002:ac8:b8d:0:0:0:0:0', 'indicator_type': 'IPv6'},
            {'value': 'demisto.com:369/rest/of/path', 'indicator_type': 'URL'},
            {'value': 'panw.com/path', 'indicator_type': 'URL'},
            {'value': '*.domain.com', 'indicator_type': 'URL'},
        ]

        request_args = RequestArguments(query='', drop_invalids=True, url_port_stripping=True)
        returned_output = format_indicators(iocs, request_args)
        assert '2603:1006:1400::/40' in returned_output
        assert '2002:ac8:b8d:0:0:0:0:0' in returned_output
        assert 'demisto.com/rest/of/path' in returned_output  # port stripping
        assert 'panw.com/path' in returned_output
        assert '*.domain.com' in returned_output
        assert 'domain.com' in returned_output  # PAN-OS URLs
        assert len(returned_output) == 6

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
