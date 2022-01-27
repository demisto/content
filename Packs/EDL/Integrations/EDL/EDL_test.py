"""Imports"""
import json
import tempfile

import pytest
import os
from tempfile import mkdtemp
import demistomock as demisto
from EDL import DONT_COLLAPSE, initialize_edl_context, get_indicators_to_format

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
        RequestArguments.CTX_EMPTY_EDL_COMMENT_KEY: True,
        RequestArguments.CTX_OUT_FORMAT: 'text',
        RequestArguments.CTX_MWG_TYPE: 'string',
        RequestArguments.CTX_CATEGORY_DEFAULT: 'bc_category',
        RequestArguments.CTX_CATEGORY_ATTRIBUTE: [],
        RequestArguments.CTX_FIELDS_TO_PRESENT: 'name,type',
        RequestArguments.CTX_CSV_TEXT: False,
        RequestArguments.CTX_PROTOCOL_STRIP_KEY: False,
        RequestArguments.CTX_URL_TRUNCATE_KEY: False
    }

    request_args = RequestArguments(
        query=context_json[RequestArguments.CTX_QUERY_KEY],
        limit=context_json[RequestArguments.CTX_LIMIT_KEY],
        offset=context_json[RequestArguments.CTX_OFFSET_KEY],
        url_port_stripping=context_json[RequestArguments.CTX_PORT_STRIP_KEY],
        drop_invalids=context_json[RequestArguments.CTX_PORT_STRIP_KEY],
        collapse_ips=context_json[RequestArguments.CTX_COLLAPSE_IPS_KEY],
        add_comment_if_empty=context_json[RequestArguments.CTX_EMPTY_EDL_COMMENT_KEY],
        out_format=context_json[RequestArguments.CTX_OUT_FORMAT],
        mwg_type=context_json[RequestArguments.CTX_MWG_TYPE],
        category_default=context_json[RequestArguments.CTX_CATEGORY_DEFAULT],
        category_attribute='',
        fields_to_present=context_json[RequestArguments.CTX_FIELDS_TO_PRESENT],
        csv_text=context_json[RequestArguments.CTX_CSV_TEXT],
        url_protocol_stripping=context_json[RequestArguments.CTX_PROTOCOL_STRIP_KEY],
        url_truncate=context_json[RequestArguments.CTX_URL_TRUNCATE_KEY]
    )

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
        edl.EDL_ON_DEMAND_CACHE_PATH = 'test_data/iocs_cache_values_text.txt'
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

    def test_iterable_to_str_1(self):
        """Test invalid"""
        from EDL import iterable_to_str, DemistoException
        with pytest.raises(DemistoException):
            invalid_list_value = 2
            iterable_to_str(invalid_list_value)

    def test_iterable_to_str_2(self):
        """Test empty"""
        from EDL import iterable_to_str
        assert iterable_to_str(None) == ''
        assert iterable_to_str([]) == ''
        assert iterable_to_str({}) == ''

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

    def test_create_new_edl(self, mocker):
        """Sanity"""
        import EDL as edl
        f = tempfile.TemporaryFile(mode='w+t')
        f.write('{"value": "https://google.com", "indicator_type": "URL"}\n'
                '{"value": "demisto.com:7000", "indicator_type": "URL"}\n'
                '{"value": "demisto.com/qwertqwertyuioplkjhgfdsazxqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyu'
                'iopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopyuioplkjhgfdsa'
                'zxqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwert'
                'yuiopqwertyuiopqwertyuiopqwertyuiop", "indicator_type": "URL"}\n'
                '{"value": "demisto.com", "indicator_type": "URL"}')

        mocker.patch.object(edl, 'get_indicators_to_format', return_value=f)
        request_args = edl.RequestArguments(query='', limit=3, url_port_stripping=True, url_protocol_stripping=True,
                                            url_truncate=True)
        edl_vals = edl.create_new_edl(request_args)

        assert edl_vals == 'google.com\ndemisto.com\ndemisto.com/qwertqwertyuioplkjhgfdsazxqwertyuiopqwertyuiopq' \
                           'wertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwert' \
                           'yuiopqwertyuiopqwertyuiopyuioplkjhgfdsazxqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwe' \
                           'rtyuiopqwertyuiopqwertyuiop\n'
        f = tempfile.TemporaryFile(mode='w+t')
        f.write('{"value": "https://google.com", "indicator_type": "URL"}\n'
                '{"value": "demisto.com:7000", "indicator_type": "URL"}\n'
                '{"value": "demisto.com/qwertqwertyuioplkjhgfdsazxqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyu'
                'iopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopyuioplkjhgfdsa'
                'zxqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwert'
                'yuiopqwertyuiopqwertyuiopqwertyuiop", "indicator_type": "URL"}\n'
                '{"value": "demisto.com", "indicator_type": "URL"}')
        mocker.patch.object(edl, 'get_indicators_to_format', return_value=f)
        request_args = edl.RequestArguments(out_format='CSV', query='', limit=3, url_port_stripping=True,
                                            url_protocol_stripping=True, url_truncate=True, fields_to_present='name,value')
        edl_v = edl.create_new_edl(request_args)
        assert edl_v == '{"value": "https://google.com", "indicator_type": "URL"}\n' \
                        '{"value": "demisto.com:7000", "indicator_type": "URL"}\n' \
                        '{"value": "demisto.com/qwertqwertyuioplkjhgfdsazxqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyu' \
                        'iopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopyuioplkjhgfdsa' \
                        'zxqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwert' \
                        'yuiopqwertyuiopqwertyuiopqwertyuiop", "indicator_type": "URL"}\n' \
                        '{"value": "demisto.com", "indicator_type": "URL"}' \


    def test_create_json_out_format(self):
        """
        Given:
          - RequestArguments
          - Indicator info
        When:
          - request json outbound format
        Then:
          - assert the result
        """
        from EDL import create_json_out_format, RequestArguments
        returned_output = []
        with open('test_data/demisto_url_iocs.json', 'r') as iocs_json_f:
            iocs_json = json.loads(iocs_json_f.read())

            # strips port numbers
            request_args = RequestArguments(query='', drop_invalids=True, url_port_stripping=True)
            for ioc in iocs_json:
                returned_output.append(create_json_out_format(['value', 'indicator_type'], ioc, request_args, True))
            assert returned_output == [', {"value": "1.2.3.4/wget", "indicator_type": "URL"}',
                                       ', {"value": "https://www.demisto.com/cool", "indicator_type": "URL"}',
                                       ', {"value": "https://www.demisto.com/*cool", "indicator_type": "URL"}']
            returned_output = ''
            not_first_call = False
            for ioc in iocs_json:
                returned_output += (create_json_out_format([], ioc, request_args, not_first_call))
                not_first_call = True
            returned_output += ']'
            assert json.loads(returned_output) == iocs_json

    def test_create_csv_out_format(self):
        """
        Given:
          - RequestArguments
          - Indicator info With CustomFields
        When:
          - request csv outbound format
        Then:
          - assert the result
        """
        from EDL import create_csv_out_format, RequestArguments
        with open('test_data/demisto_url_iocs.json', 'r') as iocs_json_f:
            iocs_json = json.loads(iocs_json_f.read())
            request_args = RequestArguments(query='', drop_invalids=True, url_port_stripping=True,
                                            url_protocol_stripping=True)
            returned_output = ''
            not_first_call = False
            for ioc in iocs_json:
                returned_output += (create_csv_out_format(not_first_call, ['value', 'indicator_type', 'test'], ioc,
                                                          request_args))
                not_first_call = True

            assert returned_output == 'name,type\n"1.2.3.4/wget","URL","test"\n"www.demisto.com/cool","URL","test"\n' \
                                      '"www.demisto.com/*cool","URL","None"'

    def test_create_mwg_out_format(self):
        """
        Given:
          - RequestArguments
          - Indicator info
        When:
          - request mwg outbound format
        Then:
          - assert the result
        """
        from EDL import create_mwg_out_format, RequestArguments
        with open('test_data/demisto_url_iocs.json', 'r') as iocs_json_f:
            iocs_json = json.loads(iocs_json_f.read())
            request_args = RequestArguments(query='', drop_invalids=True, url_port_stripping=True,
                                            url_protocol_stripping=True)
            returned_output = ''
            not_first_call = False
            for ioc in iocs_json:
                returned_output += (
                    create_mwg_out_format(ioc, request_args, not_first_call))
                not_first_call = True

            assert returned_output == 'type=string\n"1.2.3.4/wget" "AutoFocus Feed"\n"www.demisto.com/cool" ' \
                                      '"AutoFocus V2,VirusTotal,Alien Vault OTX TAXII Feed"\n"www.demisto.com/*cool" ' \
                                      '"AutoFocus V2,VirusTotal,Alien Vault OTX TAXII Feed"'

    def test_create_proxysg_out_format(self):
        """
        Given:
          - RequestArguments
          - Indicator info
        When:
          - request proxysg outbound format
        Then:
          - assert files_by_category as 3 keys
          - assert the result
        """
        from EDL import create_proxysg_out_format, RequestArguments, create_proxysg_all_category_out_format
        files_by_category = {}
        with open('test_data/demisto_url_iocs.json', 'r') as iocs_json_f:
            iocs_json = json.loads(iocs_json_f.read())

        request_args = RequestArguments(query='', drop_invalids=True, url_port_stripping=True,
                                        url_protocol_stripping=True)
        for ioc in iocs_json:
            files_by_category = create_proxysg_out_format(ioc, files_by_category, request_args)

        assert len(files_by_category) == 3
        result_file = tempfile.TemporaryFile(mode='w+t')
        result_file = create_proxysg_all_category_out_format(result_file, files_by_category)
        result_file.seek(0)
        assert result_file.read() == 'define category category1\n1.2.3.4/wget\nend\ndefine category category2\n' \
                                     'www.demisto.com/cool\nend\ndefine category bc_category\nwww.demisto.com/*cool\n' \
                                     'end'

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
        ip_list = ["1.1.1.1", "25.24.23.22", "22.21.20.19", "1.1.1.2", "1.2.3.4", "1.1.1.3", "2.2.2.2", "1.2.3.5",
                   "3.3.3.0/30", '3.3.3.1']

        ip_range_list = ips_to_ranges(ip_list, COLLAPSE_TO_RANGES)
        assert "1.1.1.1-1.1.1.3" in ip_range_list
        assert "1.2.3.4-1.2.3.5" in ip_range_list
        assert "1.1.1.2" not in ip_range_list
        assert "2.2.2.2" in ip_range_list
        assert "25.24.23.22" in ip_range_list
        assert "3.3.3.0-3.3.3.3" in ip_range_list

    def test_ips_to_ranges_cidr(self):
        from EDL import ips_to_ranges, COLLAPSE_TO_CIDR
        ip_list = ["1.1.1.1", "25.24.23.22", "22.21.20.19", "1.1.1.2", "1.2.3.4", "1.1.1.3", "2.2.2.2", "1.2.3.5",
                   "3.3.3.0/30", '3.3.3.1']

        ip_range_list = ips_to_ranges(ip_list, COLLAPSE_TO_CIDR)
        assert "1.1.1.1" in ip_range_list
        assert "1.1.1.2/31" in ip_range_list
        assert "1.2.3.4/31" in ip_range_list
        assert "1.2.3.5" not in ip_range_list
        assert "1.1.1.3" not in ip_range_list
        assert "2.2.2.2" in ip_range_list
        assert "25.24.23.22" in ip_range_list
        assert "3.3.3.0/30" in ip_range_list

    def test_ips_to_cidrs_bad_ip(self):
        from EDL import ips_to_ranges, COLLAPSE_TO_CIDR
        ip_list = ["1.1.1.1", "1.1.1.2", "1.1.1.3", "1.2.3.4", "1.2.3.5", "doesntwork/oh"]

        ip_range_list = ips_to_ranges(ip_list, COLLAPSE_TO_CIDR)
        assert "1.1.1.1" in ip_range_list
        assert "1.1.1.2/31" in ip_range_list
        assert "1.2.3.4/31" in ip_range_list
        assert "doesntwork/oh" in ip_range_list
        assert "1.2.3.5" not in ip_range_list
        assert "1.1.1.3" not in ip_range_list

    def test_ips_to_ranges_bad_ip(self):
        from EDL import ips_to_ranges, COLLAPSE_TO_RANGES
        ip_list = ["1.1.1.1", "doesntwork/oh"]

        ip_range_list = ips_to_ranges(ip_list, COLLAPSE_TO_RANGES)
        assert "1.1.1.1" in ip_range_list
        assert "doesntwork/oh" in ip_range_list

    def test_is_valid_ip_ipv4(self):
        from EDL import is_valid_ip
        ip = '1.1.1.1'
        assert is_valid_ip(ip)

    def test_is_valid_ip_ipv6(self):
        from EDL import is_valid_ip
        ip = '2001:0db8:85a3:0000:0000:8a2e:0370:7334'
        assert is_valid_ip(ip)

    def test_is_valid_ip_cidr(self):
        from EDL import is_valid_ip
        cidr = '1.2.3.5/10'
        assert not is_valid_ip(cidr)

    def test_is_valid_ip_invalid_ip(self):
        from EDL import is_valid_ip
        ip = 'This is not an IP, this is just a String'
        assert not is_valid_ip(ip)

    def test_is_valid_cidr_ipv4_network(self):
        from EDL import is_valid_cidr
        cidr = '1.2.3.5/10'
        assert is_valid_cidr(cidr)

    def test_is_valid_cidr_ipv6_network(self):
        from EDL import is_valid_cidr
        cidr = '2001:0db8:85a3:0000:0000:8a2e:0370:7334/10'
        assert is_valid_cidr(cidr)

    def test_is_valid_cidr_ip_address(self):
        from EDL import is_valid_cidr
        ip = '1.1.1.1'
        assert not is_valid_cidr(ip)

    def test_is_valid_cidr_not_a_cidr(self):
        from EDL import is_valid_cidr
        cidr = 'This is not a CIDR / this is just a String'
        assert not is_valid_cidr(cidr)

    def test_get_bool_arg_or_param(self):
        """
        Given:
          - bool arg that is not in args
          - bool arg that is in args and is in params
          - bool arg that is not in args but is in params
        When:
          - calling get_bool_arg_or_param
        Then:
          - return False
          - return arg bool equivelant value
          - return param bool value
        """
        from EDL import get_bool_arg_or_param
        existing_key = 'exists'
        missing_key = 'missing'
        args = {
            existing_key: 'true'
        }
        params = {
            existing_key: False,
            missing_key: True
        }

        # missing from both
        assert get_bool_arg_or_param(args, params, '') is False

        # exists in args and params
        assert get_bool_arg_or_param(args, params, existing_key) is True

        # exists in params only
        assert get_bool_arg_or_param(args, params, missing_key) is True

    def test_get_request_args(self):
        """
        Test get_request_args sets RequestArgs with priority to request_args and params as fallback
        """
        from EDL import get_request_args, COLLAPSE_TO_CIDR, COLLAPSE_TO_RANGES
        limit = 100
        offset = '1'
        query = 'q'
        strip_port = True
        drop_invalids = True
        add_comment_if_empty = True
        request_args = {
            'n': limit,
            's': offset,
            'q': query,
            'sp': strip_port,
            'di': drop_invalids,
            'tr': 1,
            'ce': add_comment_if_empty,
            'v': 'CSV'
        }
        params = {
            'edl_size': limit + 1,
            'indicators_query': query + '42',
            'url_port_stripping': not strip_port,
            'drop_invalids': not drop_invalids,
            'collapse_ips': 2,
            'add_comment_if_empty': not add_comment_if_empty,
            'format': 'CSV'
        }

        # request with no request_args
        res = get_request_args({}, params)
        assert res.limit == params['edl_size']
        assert res.query == params['indicators_query']
        assert res.url_port_stripping == params['url_port_stripping']
        assert res.drop_invalids == params['drop_invalids']
        assert res.collapse_ips == COLLAPSE_TO_CIDR
        assert res.add_comment_if_empty == params['add_comment_if_empty']

        # request with full request_args
        res = get_request_args(request_args, params)
        assert res.limit == request_args['n']
        assert res.query == request_args["q"]
        assert res.url_port_stripping == request_args["sp"]
        assert res.drop_invalids == request_args["di"]
        assert res.collapse_ips == COLLAPSE_TO_RANGES
        assert res.add_comment_if_empty == request_args["ce"]


def test_initialize_edl_context():
    """
    Given:
      - the params
    When:
      - config the instance
    Then:
      - assert the integrationContext is saved properly
    """
    params = {'edl_size': '200',
              'indicators_query': '*',
              'collapse_ips': DONT_COLLAPSE,
              'url_port_stripping': False,
              'url_protocol_stripping': True,
              'drop_invalids': True,
              'add_comment_if_empty': False,
              'mwg_type': "string",
              'category_default': 'bc_category',
              'category_attribute': 'test1,test2',
              'fields_filter': 'value,type',
              'format': 'CSV',
              'csv_text': True,
              'url_truncate': False}

    initialize_edl_context(params)
    assert demisto.integrationContext == {'last_query': '*',
                                          'out_format': 'CSV',
                                          'last_limit': 200,
                                          'last_offset': 0,
                                          'drop_invalids': True,
                                          'url_port_stripping': False,
                                          'collapse_ips': "Don't Collapse",
                                          'add_comment_if_empty': False,
                                          'mwg_type': 'string',
                                          'bc_category': 'bc_category',
                                          'category_attribute': ['test1', 'test2'],
                                          'fields_to_present': 'name,type',
                                          'csv_text': True,
                                          'url_protocol_stripping': True,
                                          'url_truncate': False,
                                          'UpdateEDL': True
                                          }


class IndicatorsSearcher:
    # an IndicatorsSearcher class for testing
    def __init__(self, limit=None):
        self._limit = limit
        self._corrent = 0
        self.ioc = [{'iocs': [{"value": "https://google.com", "indicator_type": "URL"}]},
                    {'iocs': [{"value": "demisto.com:7000", "indicator_type": "URL"}]},
                    {'iocs': [{"value": "demisto.com/qwertqwer", "indicator_type": "URL"}]},
                    {'iocs': [{"value": "demisto.com", "indicator_type": "URL"}]}]

    def __iter__(self):
        return self

    def __next__(self):
        if self._corrent >= self._limit:
            raise StopIteration
        res = self.ioc[self._corrent]
        self._corrent += 1
        return res

    @property
    def limit(self):
        return self._limit


def test_get_indicators_to_format_csv():
    """
    Given:
      - IndicatorsSearcher with indicators
      - request_args of the coll
    When:
      - request indicators on csv format
    Then:
      - assert the indicators are returned properly for the requested format
    """
    import EDL as edl
    indicator_searcher = IndicatorsSearcher(4)
    request_args = edl.RequestArguments(out_format='CSV', query='', limit=3, url_port_stripping=True,
                                        url_protocol_stripping=True, url_truncate=True, fields_to_present='name,type')
    f = get_indicators_to_format(indicator_searcher, request_args)
    f.seek(0)
    indicators = f.read()
    assert indicators == 'name,type\n"google.com","URL"\n"demisto.com","URL"\n"demisto.com/qwertqwer","URL"\n"demisto.com","URL"'


def test_get_indicators_to_format_json():
    """
    Given:
      - IndicatorsSearcher with indicators
      - request_args of the coll
    When:
      - request indicators on json format
    Then:
      - assert the indicators are returned properly for the requested format
    """
    import EDL as edl
    indicator_searcher = IndicatorsSearcher(4)
    request_args = edl.RequestArguments(out_format='JSON', query='', limit=3, url_port_stripping=True,
                                        url_protocol_stripping=True, url_truncate=True, fields_to_present='name,type')
    f = get_indicators_to_format(indicator_searcher, request_args)
    f.seek(0)
    indicators = f.read()
    assert indicators == '[{"value": "google.com", "indicator_type": "URL"}, {"value": "demisto.com", "indicator_type": "URL"}, {"value": "demisto.com/qwertqwer", "indicator_type": "URL"}, {"value": "demisto.com", "indicator_type": "URL"}]'


def test_get_indicators_to_format_mwg():
    """
    Given:
      - IndicatorsSearcher with indicators
      - request_args of the coll
    When:
      - request indicators on mwg format
    Then:
      - assert the indicators are returned properly for the requested format
    """
    import EDL as edl
    indicator_searcher = IndicatorsSearcher(4)
    request_args = edl.RequestArguments(out_format='McAfee Web Gateway', query='', limit=3, url_port_stripping=True,
                                        url_protocol_stripping=True, url_truncate=True)
    f = get_indicators_to_format(indicator_searcher, request_args)
    f.seek(0)
    indicators = f.read()
    assert indicators == 'type=string\n"google.com" "from CORTEX XSOAR"\n"demisto.com" "from CORTEX XSOAR"\n"demisto.com/qwertqwer" "from CORTEX XSOAR"\n"demisto.com" "from CORTEX XSOAR"'


def test_get_indicators_to_format_symantec():
    """
    Given:
      - IndicatorsSearcher with indicators
      - request_args of the coll
    When:
      - request indicators on symantec format
    Then:
      - assert the indicators are returned properly for the requested format
    """
    import EDL as edl
    indicator_searcher = IndicatorsSearcher(4)
    request_args = edl.RequestArguments(out_format='Symantec ProxySG', query='', limit=3, url_port_stripping=True,
                                        url_protocol_stripping=True, url_truncate=True)
    f = get_indicators_to_format(indicator_searcher, request_args)
    f.seek(0)
    indicators = f.read()
    assert indicators == 'define category bc_category\ngoogle.com\ndemisto.com\ndemisto.com/qwertqwer\ndemisto.com\nend'


def test_get_indicators_to_format_text():
    """
    Given:
      - IndicatorsSearcher with indicators
      - request_args of the coll
    When:
      - request indicators on text format
    Then:
      - assert the indicators are returned properly for the requested format
    """
    import EDL as edl
    indicator_searcher = IndicatorsSearcher(4)
    request_args = edl.RequestArguments(out_format='PAN-OS (text)', query='', limit=3, url_port_stripping=True,
                                        url_protocol_stripping=True, url_truncate=True)
    f = get_indicators_to_format(indicator_searcher, request_args)
    f = edl.create_text_out_format(f, request_args)

    f.seek(0)
    indicators = f.read()
    assert indicators == 'google.com\ndemisto.com\ndemisto.com/qwertqwer\ndemisto.com'