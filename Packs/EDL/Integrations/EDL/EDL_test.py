"""Imports"""
import io
import json
import tempfile
import zipfile

import pytest
import os
from tempfile import mkdtemp
import demistomock as demisto
from EDL import DONT_COLLAPSE, initialize_edl_context, get_indicators_to_format, check_platform_and_version, datetime, timezone
from freezegun import freeze_time

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
        RequestArguments.CTX_URL_TRUNCATE_KEY: False,
        RequestArguments.CTX_NO_TLD: True,
        RequestArguments.CTX_MAXIMUM_CIDR: 8
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
        url_truncate=context_json[RequestArguments.CTX_URL_TRUNCATE_KEY],
        no_wildcard_tld=context_json[RequestArguments.CTX_NO_TLD],
        maximum_cidr_size=context_json[RequestArguments.CTX_MAXIMUM_CIDR],
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
        edl.EDL_ON_DEMAND_CACHE_ORIGINAL_SIZE = 40
        mocker.patch.object(edl, 'get_integration_context', return_value={})
        actual_edl, original_indicators_count = edl.get_edl_on_demand()

        with open(edl.EDL_ON_DEMAND_CACHE_PATH) as f:
            expected_edl = f.read()

        assert actual_edl == expected_edl
        assert original_indicators_count == edl.EDL_ON_DEMAND_CACHE_ORIGINAL_SIZE

    @freeze_time("2024-04-04 03:21:34")
    def test_get_edl_on_demand__with_refresh_signal(self, mocker):
        """
        Test get_edl_on_demand fetches new indicators and stores them to cache when key is passed
        Given:
            - refresh signal in context
        When:
            - calling get_edl_on_demand
        Then:
            - save the edl to the system file
            - assert the edl log is as expected
        """
        import EDL as edl
        expected_edl = "8.8.8.8"
        edl_log_line = "\nAdded | 8.8.8.8 | 8.8.8.8 | Found new Domain."
        ctx = {edl.EDL_ON_DEMAND_KEY: True, edl.RequestArguments.CTX_QUERY_KEY: "*"}
        tmp_dir = mkdtemp()
        edl.EDL_ON_DEMAND_CACHE_PATH = os.path.join(tmp_dir, 'cache')
        mocker.patch.object(edl, 'get_integration_context', return_value=ctx)
        mocker.patch.object(edl, 'create_new_edl', return_value=(expected_edl, 1, {'Added': 1}))
        created_time = datetime.now(timezone.utc)

        with tempfile.NamedTemporaryFile() as wip_log_file, tempfile.NamedTemporaryFile() as log_file, \
                tempfile.NamedTemporaryFile() as cached_edl_file:
            edl.EDL_FULL_LOG_PATH_WIP = wip_log_file.name
            edl.EDL_FULL_LOG_PATH = log_file.name
            edl.EDL_ON_DEMAND_CACHE_PATH = cached_edl_file.name
            wip_log_file.write(edl_log_line.encode())
            wip_log_file.seek(0)
            actual_edl, _ = edl.get_edl_on_demand()
            edl_log = log_file.read()
            edl_log = edl_log.decode("utf-8")
            cached_edl = cached_edl_file.read()

        assert actual_edl == expected_edl == cached_edl.decode("utf-8")
        expected_edl_log = f"# Created new EDL at {created_time.isoformat()}\n\n" \
                           f"## Configuration Arguments: {{'last_query': '*', 'out_format': 'PAN-OS (text)', " \
                           f"'last_limit': 10000, 'last_offset': 0, 'drop_invalids': False, 'url_port_stripping': False, " \
                           f"'collapse_ips': \"Don't Collapse\", 'add_comment_if_empty': True, 'mwg_type': 'string', " \
                           f"'bc_category': 'bc_category', 'category_attribute': [], 'fields_to_present': 'name,type', " \
                           f"'csv_text': False, 'url_protocol_stripping': False, 'url_truncate': False, " \
                           f"'maximum_cidr_size': 8, 'no_wildcard_tld': False}}\n\n" \
                           f"## EDL stats: 1 indicators in total, 0 modified, 0 dropped, 1 added.\n\n" \
                           f"Action | Indicator | Raw Indicator | Reason{edl_log_line}"

        assert edl_log == expected_edl_log

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

        mocker.patch.object(edl, 'get_indicators_to_format', return_value=(f, 4))
        request_args = edl.RequestArguments(query='', limit=3, url_port_stripping=True, url_protocol_stripping=True,
                                            url_truncate=True)
        with tempfile.NamedTemporaryFile() as wip_log_file:
            edl.EDL_FULL_LOG_PATH_WIP = wip_log_file.name
            edl_vals, original_indicators_count, edl_log_stats = edl.create_new_edl(request_args)
            edl_log = wip_log_file.read()
            edl_log = edl_log.decode("utf-8")

        assert edl_vals == 'google.com\ndemisto.com\ndemisto.com/qwertqwertyuioplkjhgfdsazxqwertyuiopqwertyuiopq' \
                           'wertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwert' \
                           'yuiopqwertyuiopqwertyuiopyuioplkjhgfdsazxqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwe' \
                           'rtyuiopqwertyuiopqwertyuiop\n'

        expected_log = '\nAdded | google.com | https://google.com | Found new URL.' \
                       '\nAdded | demisto.com | demisto.com:7000 | Found new URL.' \
                       '\nAdded | demisto.com/qwertqwertyuioplkjhgfdsazxqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwe' \
                       'rtyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopyui' \
                       'oplkjhgfdsazxqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiop | demi' \
                       'sto.com/qwertqwertyuioplkjhgfdsazxqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwerty' \
                       'uiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopyuioplkjhgfdsazx' \
                       'qwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiop' \
                       'qwertyuiopqwertyuiopqwertyuiopqwertyuiop | Found new URL.' \
                       '\nAdded | demisto.com | demisto.com | Found new URL.'

        assert edl_log == expected_log
        assert edl_log_stats == {'Added': 4}
        f = tempfile.TemporaryFile(mode='w+t')
        f.write('{"value": "https://google.com", "indicator_type": "URL"}\n'
                '{"value": "demisto.com:7000", "indicator_type": "URL"}\n'
                '{"value": "demisto.com/qwertqwertyuioplkjhgfdsazxqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyu'
                'iopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopyuioplkjhgfdsa'
                'zxqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwert'
                'yuiopqwertyuiopqwertyuiopqwertyuiop", "indicator_type": "URL"}\n'
                '{"value": "demisto.com", "indicator_type": "URL"}')
        mocker.patch.object(edl, 'get_indicators_to_format', return_value=(f, 4))
        request_args = edl.RequestArguments(out_format='CSV', query='', limit=3, url_port_stripping=True,
                                            url_protocol_stripping=True, url_truncate=True, fields_to_present='name,value')
        with tempfile.NamedTemporaryFile() as wip_log_file:
            edl.EDL_FULL_LOG_PATH_WIP = wip_log_file.name
            edl_v, original_indicators_count, edl_log_stats = edl.create_new_edl(request_args)
            edl_log = wip_log_file.read()
            edl_log = edl_log.decode("utf-8")

        assert edl_v == '{"value": "https://google.com", "indicator_type": "URL"}\n' \
                        '{"value": "demisto.com:7000", "indicator_type": "URL"}\n' \
                        '{"value": "demisto.com/qwertqwertyuioplkjhgfdsazxqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyu' \
                        'iopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopyuioplkjhgfdsa' \
                        'zxqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwert' \
                        'yuiopqwertyuiopqwertyuiopqwertyuiop", "indicator_type": "URL"}\n' \
                        '{"value": "demisto.com", "indicator_type": "URL"}'
        assert edl_log == ''  # No log when exporting to csv
        assert edl_log_stats == {}  # No log when exporting to csv

    def test_create_new_edl_edge_cases(self, mocker, requests_mock):
        """
        Test create_new_edl with wildcards, cidrs with prefix and non-ascii chars
        Given:
            - A list of indicators of "edge cases"
        When:
            - calling create_new_edl
        Then:
            - Ensure that the list is the same as is should.
            - Ensure the log is as expected.
        """

        import EDL as edl
        tlds = 'com\nco.uk'
        requests_mock.get('https://publicsuffix.org/list/public_suffix_list.dat', text=tlds)
        requests_mock.get('https://raw.githubusercontent.com/publicsuffix/list/master/public_suffix_list.dat', text=tlds)
        indicators = [{'value': '1.1.1.1/7', 'indicator_type': 'CIDR'},  # prefix=7
                      {"value": "1.1.1.1/12", "indicator_type": "CIDR"},  # prefix=12
                      {"value": "*.com", "indicator_type": "Domain"},  # tld
                      {"value": "*.co.uk", "indicator_type": "Domain"},  # tld
                      {"value": "*.google.com", "indicator_type": "Domain"},  # no tld
                      {"value": "aא.com", "indicator_type": "URL"}]  # no ascii
        f = '\n'.join(json.dumps(indicator) for indicator in indicators)
        request_args = edl.RequestArguments(collapse_ips=DONT_COLLAPSE, maximum_cidr_size=2)
        mocker.patch.object(edl, 'get_indicators_to_format', return_value=(io.StringIO(f), 6))
        with tempfile.NamedTemporaryFile() as wip_log_file:
            edl.EDL_FULL_LOG_PATH_WIP = wip_log_file.name
            edl_v, _, edl_log_stats = edl.create_new_edl(request_args)
            edl_log = wip_log_file.read()
            edl_log = edl_log.decode("utf-8")

        expected_values = set()
        for indicator in indicators:
            value = indicator.get('value')
            if value.startswith('*.'):
                expected_values.add(value.lstrip('*.'))
            expected_values.add(value)
        assert set(edl_v.split('\n')) == expected_values
        expected_log = '\nAdded | 1.1.1.1/7 | 1.1.1.1/7 | Found new CIDR.' \
                       '\nAdded | 1.1.1.1/12 | 1.1.1.1/12 | Found new CIDR.' \
                       '\nAdded | *.com | *.com | Found new Domain.' \
                       '\nAdded | *.co.uk | *.co.uk | Found new Domain.' \
                       '\nAdded | *.google.com | *.google.com | Found new Domain.' \
                       '\nAdded | aא.com | aא.com | Found new URL.'
        assert edl_log == expected_log
        assert edl_log_stats == {'Added': 6}

        request_args = edl.RequestArguments(collapse_ips=DONT_COLLAPSE, maximum_cidr_size=8)
        mocker.patch.object(edl, 'get_indicators_to_format', return_value=((io.StringIO(f)), 6))
        with tempfile.NamedTemporaryFile() as wip_log_file:
            edl.EDL_FULL_LOG_PATH_WIP = wip_log_file.name
            edl_v, _, edl_log_stats = edl.create_new_edl(request_args)
            edl_log = wip_log_file.read()
            edl_log = edl_log.decode("utf-8")

        assert set(edl_v.split('\n')) == {"1.1.1.1/12", "*.com", "com", "*.co.uk",
                                          "co.uk", "*.google.com", "google.com", "aא.com"}

        expected_log = '\nDropped | 1.1.1.1/7 | 1.1.1.1/7 | CIDR exceeds max length 8.' \
                       '\nAdded | 1.1.1.1/12 | 1.1.1.1/12 | Found new CIDR.' \
                       '\nAdded | *.com | *.com | Found new Domain.' \
                       '\nAdded | *.co.uk | *.co.uk | Found new Domain.' \
                       '\nAdded | *.google.com | *.google.com | Found new Domain.' \
                       '\nAdded | aא.com | aא.com | Found new URL.'
        assert edl_log == expected_log
        assert edl_log_stats == {'Added': 5, 'Dropped': 1}

        request_args = edl.RequestArguments(collapse_ips=DONT_COLLAPSE, no_wildcard_tld=True, maximum_cidr_size=13)
        mocker.patch.object(edl, 'get_indicators_to_format', return_value=(io.StringIO(f), 6))
        with tempfile.NamedTemporaryFile() as wip_log_file:
            edl.EDL_FULL_LOG_PATH_WIP = wip_log_file.name
            edl_v, _, edl_log_stats = edl.create_new_edl(request_args)
            edl_log = wip_log_file.read()
            edl_log = edl_log.decode("utf-8")

        assert set(edl_v.split('\n')) == {"*.google.com", "google.com", "aא.com"}

        expected_log = '\nDropped | 1.1.1.1/7 | 1.1.1.1/7 | CIDR exceeds max length 13.' \
                       '\nDropped | 1.1.1.1/12 | 1.1.1.1/12 | CIDR exceeds max length 13.' \
                       '\nDropped | com | *.com | Domain is a TLD.' \
                       '\nDropped | co.uk | *.co.uk | Domain is a TLD.' \
                       '\nAdded | *.google.com | *.google.com | Found new Domain.' \
                       '\nAdded | aא.com | aא.com | Found new URL.'
        assert edl_log == expected_log
        assert edl_log_stats == {'Added': 2, 'Dropped': 4}

    def test_create_new_edl_with_offset(self, mocker, requests_mock):
        """
        Test create_new_edl with and without offset
        Given:
            - A list of indicators
        When:
            - calling create_new_edl
        Then:
            - Ensure that the list is the same as is should with no offset and with offset=2
            - Ensure the log is as expected.
        """

        import EDL as edl
        tlds = 'com\nco.uk'
        requests_mock.get('https://publicsuffix.org/list/public_suffix_list.dat', text=tlds)
        requests_mock.get('https://raw.githubusercontent.com/publicsuffix/list/master/public_suffix_list.dat', text=tlds)
        indicators = [{'value': '1.1.1.1/7', 'indicator_type': 'CIDR'},  # prefix=7
                      {"value": "1.1.1.1/12", "indicator_type": "CIDR"},  # prefix=12
                      {"value": "*.com", "indicator_type": "Domain"},  # tld
                      {"value": "*.co.uk", "indicator_type": "Domain"},  # tld
                      {"value": "*.google.com", "indicator_type": "Domain"},  # no tld
                      {"value": "aא.com", "indicator_type": "URL"}]  # no ascii
        f = '\n'.join(json.dumps(indicator) for indicator in indicators)

        # create_new_edl with no offset
        request_args = edl.RequestArguments(collapse_ips=DONT_COLLAPSE, maximum_cidr_size=8)
        mocker.patch.object(edl, 'get_indicators_to_format', return_value=((io.StringIO(f)), 6))

        with tempfile.NamedTemporaryFile() as wip_log_file:
            edl.EDL_FULL_LOG_PATH_WIP = wip_log_file.name
            edl_v, _, edl_log_stats = edl.create_new_edl(request_args)
            edl_log = wip_log_file.read()
            edl_log = edl_log.decode("utf-8")

        assert set(edl_v.split('\n')) == {"1.1.1.1/12", "*.com", "com", "*.co.uk",
                                          "co.uk", "*.google.com", "google.com", "aא.com"}

        expected_log = "\nDropped | 1.1.1.1/7 | 1.1.1.1/7 | CIDR exceeds max length 8." \
                       "\nAdded | 1.1.1.1/12 | 1.1.1.1/12 | Found new CIDR." \
                       "\nAdded | *.com | *.com | Found new Domain." \
                       "\nAdded | *.co.uk | *.co.uk | Found new Domain." \
                       "\nAdded | *.google.com | *.google.com | Found new Domain." \
                       "\nAdded | aא.com | aא.com | Found new URL."
        assert edl_log == expected_log
        assert edl_log_stats == {'Added': 5, 'Dropped': 1}

        # create_new_edl with offset=2
        request_args = edl.RequestArguments(collapse_ips=DONT_COLLAPSE, maximum_cidr_size=8, offset=2)
        mocker.patch.object(edl, 'get_indicators_to_format', return_value=((io.StringIO(f)), 6))
        with tempfile.NamedTemporaryFile() as wip_log_file:
            edl.EDL_FULL_LOG_PATH_WIP = wip_log_file.name
            edl_v, _, edl_log_stats = edl.create_new_edl(request_args)
            edl_log = wip_log_file.read()
            edl_log = edl_log.decode("utf-8")
        assert set(edl_v.split('\n')) == {"google.com", "co.uk", "*.co.uk", "*.google.com", "*.com", "aא.com"}
        assert edl_log == expected_log
        assert edl_log_stats == {'Added': 5, 'Dropped': 1}

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
        with open('test_data/demisto_url_iocs.json') as iocs_json_f:
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
        with open('test_data/demisto_url_iocs.json') as iocs_json_f:
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
        with open('test_data/demisto_url_iocs.json') as iocs_json_f:
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
        with open('test_data/demisto_url_iocs.json') as iocs_json_f:
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

    def test_is_large_cidr(self):
        """
        Given:
            large CIDR (large cidr is with prefix smaller than 8
        When:
            - Calling `is_valid_cidr` with `auto_block_large_cidrs=False`
            - Calling `is_valid_cidr` with `auto_block_large_cidrs=True`
         Then:
            - Should be valid if `auto_block_large_cidrs=False`
            - Should be invalid if `auto_block_large_cidrs=False`
        """
        from EDL import is_large_cidr
        ipv4_large_cidr = '1.2.3.5/7'
        ipv6_large_cide = '2001:0db8:85a3:0000:0000:8a2e:0370:7334/8'
        assert is_large_cidr(ipv4_large_cidr, 9)
        assert is_large_cidr(ipv6_large_cide, 9)

        ipv4_small_cidr = '1.2.3.5/12'
        ipv6_small_cidr = '2001:0db8:85a3:0000:0000:8a2e:0370:7334/23'
        assert not is_large_cidr(ipv6_small_cidr, 11)
        assert not is_large_cidr(ipv4_small_cidr, 11)

        ipv4_large_cidr = '1.2.3.5/8'
        ipv6_large_cide = '2001:0db8:85a3:0000:0000:8a2e:0370:7334/8'
        assert not is_large_cidr(ipv4_large_cidr, 8)
        assert not is_large_cidr(ipv6_large_cide, 8)

    def test_is_large_cidr_not_valid(self):
        from EDL import is_large_cidr
        not_valid = "doesntwork/oh"
        assert not is_large_cidr(not_valid, 7)

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
            'format': 'CSV',
            'no_wildcard_tld': False,
            'maximum_cidr_size': '8'
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
              'url_truncate': False,
              'maximum_cidr_size': '8',
              'no_wildcard_tld': True}

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
                                          'UpdateEDL': True,
                                          'maximum_cidr_size': 8,
                                          'no_wildcard_tld': True
                                          }


class IndicatorsSearcher:
    # an IndicatorsSearcher class for testing
    def __init__(self, limit=None):
        self._limit = limit
        self._corrent = 0
        self.ioc = [{'iocs': [{"value": "https://google.com", "indicator_type": "URL"}]},
                    {'iocs': [{"value": "demisto.com:7000", "indicator_type": "URL"}]},
                    {'iocs': [{"value": "demisto.com/qwertqwer", "indicator_type": "URL"}]},
                    {'iocs': [{"value": "demisto.com", "indicator_type": "URL"}]},
                    {'iocs': [{"value": "non ascii valuè", "indicator_type": "URL"}]}, ]

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
    indicators_data, _ = get_indicators_to_format(indicator_searcher, request_args)
    indicators_data.seek(0)
    indicators = indicators_data.read()

    assert indicators == 'name,type\n"google.com","URL"\n"demisto.com","URL"\n"demisto.com/qwertqwer","URL"\n' \
                         '"demisto.com","URL"'


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
    f, _ = get_indicators_to_format(indicator_searcher, request_args)
    f.seek(0)
    indicators = f.read()
    assert indicators == '[{"value": "google.com", "indicator_type": "URL"},' \
                         ' {"value": "demisto.com", "indicator_type": "URL"},' \
                         ' {"value": "demisto.com/qwertqwer", "indicator_type": "URL"},' \
                         ' {"value": "demisto.com", "indicator_type": "URL"}]'


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
    f, _ = get_indicators_to_format(indicator_searcher, request_args)
    f.seek(0)
    indicators = f.read()
    assert indicators == 'type=string\n"google.com" "from CORTEX XSOAR"\n"demisto.com" "from CORTEX XSOAR"\n' \
                         '"demisto.com/qwertqwer" "from CORTEX XSOAR"\n"demisto.com" "from CORTEX XSOAR"'


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
    f, _ = get_indicators_to_format(indicator_searcher, request_args)
    f.seek(0)
    indicators = f.read()
    assert indicators == 'define category bc_category\ngoogle.com\ndemisto.com\ndemisto.com/qwertqwer\ndemisto.com\nend'


@pytest.mark.parametrize('port, platform, expected_res', [('', {'platform': 'xsiam', 'version': '8.1.1'}, False),
                                                          ('', {'platform': 'xsiam', 'version': '7.0.0'}, False),
                                                          ('', {'platform': 'xsoar', 'version': '7.0.0'}, True),
                                                          ('8888', {'platform': 'xsoar', 'version': '7.0.0'}, False),
                                                          ('0000', {'platform': 'xsoar', 'version': '8.4.0'}, False),
                                                          ])
def test_no_port_param_lower_than_xsoar_8(port, platform, expected_res, mocker):
    """
    Given:
        - longRuningPort param Empry with xsiam platform
        - longRuningPort param Empry with xsiam platform
        - longRuningPort param Empry with xsoar platform
        - longRuningPort param value with xsoar platform
        - longRuningPort param value with xsoar platform

    When:
        - Checking if the platform is xsoar and the version is less than 8.0.0

    Then:
        Valdiate correct expected result
        - False
        - False
        - True
        - False
        - False
    """
    mocker.patch.object(demisto, 'demistoVersion', return_value=platform)
    assert check_platform_and_version({'longRunningPort': port}) == expected_res


def test_get_indicators_to_format_text():
    """
    Given:
      - IndicatorsSearcher with indicators
      - request_args of the coll
    When:
      - request indicators on text format
    Then:
      - assert the indicators are returned properly for the requested format
      - assert the log is as expected
    """
    import EDL as edl
    indicator_searcher = IndicatorsSearcher(4)
    request_args = edl.RequestArguments(out_format='PAN-OS (text)', query='', limit=3, url_port_stripping=True,
                                        url_protocol_stripping=True, url_truncate=True)
    with tempfile.NamedTemporaryFile() as wip_log_file:
        edl.EDL_FULL_LOG_PATH_WIP = wip_log_file.name
        indicators_data, _ = get_indicators_to_format(indicator_searcher, request_args)
        indicators_data, indicators_stats = edl.create_text_out_format(indicators_data, request_args)
        indicators_log = wip_log_file.read()
        indicators_log = indicators_log.decode("utf-8")

        indicators_data.seek(0)
        indicators = indicators_data.read()

    assert indicators == 'google.com\ndemisto.com\ndemisto.com/qwertqwer\ndemisto.com'
    expected_indicators_log = '\nAdded | google.com | https://google.com | Found new URL.' \
                              '\nAdded | demisto.com | demisto.com:7000 | Found new URL.' \
                              '\nAdded | demisto.com/qwertqwer | demisto.com/qwertqwer | Found new URL.' \
                              '\nAdded | demisto.com | demisto.com | Found new URL.'
    assert indicators_log == expected_indicators_log
    assert indicators_stats == {'Added': 4}


def test_get_indicators_to_format_text_enforce_ascii(mocker):
    """
    Given:
      - IndicatorsSearcher with indicators
      - request_args of the coll
      - enforce_ascii = True
    When:
      - request indicators on text format
    Then:
      - assert the indicators are returned properly for the requested format
      - assert the log is as expected
    """
    import EDL as edl
    mocker.patch.object(demisto, 'params', return_value={'enforce_ascii': True})
    indicator_searcher = IndicatorsSearcher(5)
    request_args = edl.RequestArguments(out_format='PAN-OS (text)', query='', limit=3, url_port_stripping=True,
                                        url_protocol_stripping=True, url_truncate=True)
    with tempfile.NamedTemporaryFile() as wip_log_file:
        edl.EDL_FULL_LOG_PATH_WIP = wip_log_file.name
        indicators_data, _ = get_indicators_to_format(indicator_searcher, request_args)
        indicators_data, indicators_stats = edl.create_text_out_format(indicators_data, request_args)
        indicators_log = wip_log_file.read()
        indicators_log = indicators_log.decode("utf-8")

    indicators_data.seek(0)
    indicators = indicators_data.read()
    assert indicators == 'google.com\ndemisto.com\ndemisto.com/qwertqwer\ndemisto.com'
    expected_indicators_log = '\nAdded | google.com | https://google.com | Found new URL.' \
                              '\nAdded | demisto.com | demisto.com:7000 | Found new URL.' \
                              '\nAdded | demisto.com/qwertqwer | demisto.com/qwertqwer | Found new URL.' \
                              '\nAdded | demisto.com | demisto.com | Found new URL.'
    assert indicators_log == expected_indicators_log
    assert indicators_stats == {'Added': 4}


@pytest.mark.parametrize('raw_indicators, expected_indicators, expected_log, expected_stats',
                         [([{"value": "1.3.3.7", "indicator_type": "Domain"}], {"1.3.3.7"},
                           "Added | 1.3.3.7 | 1.3.3.7 | Found new Domain.", {'Added': 1}),
                          ([{"value": "1.1.1.1/7", "indicator_type": "CIDR"}], {""},
                           "Dropped | 1.1.1.1/7 | 1.1.1.1/7 | CIDR exceeds max length 8.", {'Dropped': 1}),
                          ([{"value": "www.Inv@l*id_token.com", "indicator_type": "Domain"}], {""},
                           "Dropped | www.Inv@l*id_token.com | www.Inv@l*id_token.com | Invalid tokens or port.", {'Dropped': 1}),
                          ([{"value": "*.com", "indicator_type": "Domain"}], {""},
                           "Dropped | com | *.com | Domain is a TLD.", {'Dropped': 1}),
                          ([{"value": "http://www.google.com", "indicator_type": "URL"}], {"www.google.com"},
                           "Added | www.google.com | http://www.google.com | Found new URL.", {'Added': 1}),
                          ([{"value": "http://www.very_long_url_example_very_long.com", "indicator_type": "URL"}], {""},
                           "Dropped | www.very_long_url_example_very_long.com | http://www.very_long_url_example_very_long.com"
                           " | URL exceeds max length 20.", {'Dropped': 1}),
                          ([{"value": "1.3.3.7", "indicator_type": "IP"},
                            {"value": "1.3.3.8", "indicator_type": "IP"},
                            {"value": "1.3.3.10", "indicator_type": "IP"}], {"1.3.3.10", "1.3.3.7-1.3.3.8"},
                           "Modified | 1.3.3.7 | 1.3.3.7 | Collapsed IPv4 To Ranges.\n"
                           "Modified | 1.3.3.8 | 1.3.3.8 | Collapsed IPv4 To Ranges.\n"
                           "Added | 1.3.3.10 | 1.3.3.10 | Found new IPv4.", {'Added': 1, 'Modified': 2}),
                          ([{"value": "1.3.3.7", "indicator_type": "IPv6"},
                            {"value": "1.3.3.8", "indicator_type": "IPv6"},
                            {"value": "1.3.3.10", "indicator_type": "IPv6"}], {"1.3.3.10", "1.3.3.7-1.3.3.8"},
                           "Modified | 1.3.3.7 | 1.3.3.7 | Collapsed IPv6 To Ranges.\n"
                           "Modified | 1.3.3.8 | 1.3.3.8 | Collapsed IPv6 To Ranges.\n"
                           "Added | 1.3.3.10 | 1.3.3.10 | Found new IPv6.", {'Added': 1, 'Modified': 2})
                          ])
def test_create_log_str_from_indicators(raw_indicators, expected_indicators, expected_log, expected_stats):
    """
    Given:
        - Indicator list.
        - Strict request arguments.
        Cases:
            Case 1: Valid new Domain.
            Case 2: CIDR exceeds max length.
            Case 3: Invalid tokens or port.
            Case 4: Domain is a TLD.
            Case 5: Valid new URL.
            Case 6: URL exceeds max length
            Case 7: Collapsed some IPv4 To Ranges.
            Case 8: Collapsed some IPv6 To Ranges
    When:
        - Running create_text_out_format with out_format PAN-OS (text).
    Then:
        - Ensure the log lines are as expected.
        - Ensure the indicator list is as expected.

    """
    import EDL as edl
    edl_request_args = edl.RequestArguments(out_format='PAN-OS (text)', query='', limit=3, url_port_stripping=True,
                                            url_protocol_stripping=True, url_truncate=False, drop_invalids=True,
                                            collapse_ips="To Ranges", no_wildcard_tld=True, maximum_cidr_size=8)
    indicators_file = tempfile.TemporaryFile(mode='w+t')
    for raw_indicator in raw_indicators:
        indicators_file.write(json.dumps(raw_indicator))
        indicators_file.write("\n")
    indicators_file.seek(0)
    edl.PAN_OS_MAX_URL_LEN = 20
    with tempfile.NamedTemporaryFile() as log_file, tempfile.NamedTemporaryFile() as wip_log_file:
        edl.EDL_FULL_LOG_PATH = log_file.name
        edl.EDL_FULL_LOG_PATH_WIP = wip_log_file.name
        indicators_data, indicators_stats = edl.create_text_out_format(indicators_file, edl_request_args)

        indicators_data.seek(0)
        indicators = indicators_data.read()

        expected_log_entries = expected_log.split("\n")
        log_lines = log_file.readlines()

    for log_line in log_lines:
        assert log_line in expected_log_entries

    indicator_lines = indicators.split("\n")
    assert set(indicator_lines) == expected_indicators
    assert indicators_stats == expected_stats


def test_route_edl_log(mocker):
    """
    Given:
        - Append and prepend strings in demisto params.
        - A stored log in the relevant file.
    When:
        - A request to the '/log' endpoint is sent.
    Then:
        - Ensure the contents of the returned log are as the one stored in the file with append and prepend strings.
    """
    import EDL as edl

    mocker.patch.object(demisto, 'params', return_value={'append_string': '+append_string+',
                                                         'prepend_string': '+prepend_string+',
                                                         'cache_refresh_rate': '30 minutes'})
    request_args = edl.RequestArguments()

    mocker.patch.object(edl, 'authenticate_app', return_value=None)
    mocker.patch.object(edl, 'get_request_args', return_value=request_args)
    log_content = "test log"
    with tempfile.NamedTemporaryFile() as log_file:
        edl.EDL_FULL_LOG_PATH = log_file.name
        with open(edl.EDL_FULL_LOG_PATH, "w+") as f:
            f.write(log_content)

        test_app = edl.APP.test_client()
        response = test_app.get('/log')

    assert response.status_code == 200
    assert response.data.decode() == f'+prepend_string+\n{log_content}+append_string+'


def test_route_edl_log_empty(mocker):
    """
    Given:
        - Append and prepend strings in demisto params.
        - An empty log in the stored log file.
    When:
        - A request to the '/log' endpoint is sent.
    Then:
        - Ensure the comment '# Empty' is returned.
    """
    import EDL as edl

    mocker.patch.object(demisto, 'params', return_value={'append_string': '+append_string+',
                                                         'prepend_string': '+prepend_string+',
                                                         'cache_refresh_rate': '30 minutes'})
    request_args = edl.RequestArguments()

    mocker.patch.object(edl, 'authenticate_app', return_value=None)
    mocker.patch.object(edl, 'get_request_args', return_value=request_args)
    with tempfile.NamedTemporaryFile() as log_file:
        edl.EDL_FULL_LOG_PATH = log_file.name
        with open(edl.EDL_FULL_LOG_PATH, "w+") as f:
            f.write('')

        test_app = edl.APP.test_client()
        response = test_app.get('/log')

    assert response.status_code == 200
    assert response.data.decode() == '# Empty'


@freeze_time("2024-04-04 03:21:34")
def test_route_edl_log_too_big(mocker):
    """
    Given:
        - A stored log in the relevant file that is too big to display.
    When:
        - A request to the '/log' endpoint is sent.
    Then:
        - Ensure the first response indicates that a file will be returned.
        - Ensure the contents of the returned log are as the one stored in the file.
        - Ensure the file is returned and saved as zip.
    """
    import EDL as edl

    mocker.patch.object(demisto, 'params', return_value={'cache_refresh_rate': '30 minutes'})
    request_args = edl.RequestArguments()
    edl.MAX_DISPLAY_LOG_FILE_SIZE = 2

    mocker.patch.object(edl, 'authenticate_app', return_value=None)
    mocker.patch.object(edl, 'get_request_args', return_value=request_args)
    log_content = "test log"
    with tempfile.NamedTemporaryFile() as log_file:
        edl.EDL_FULL_LOG_PATH = log_file.name
        with open(edl.EDL_FULL_LOG_PATH, "w+") as f:
            f.write(log_content)

        test_app = edl.APP.test_client()
        first_response = test_app.get('/log')
        second_response = test_app.get('/log')

    assert first_response.status_code == 200
    assert first_response.data.decode() == '# Log exceeds max size. Refresh to download as file.'
    assert second_response.status_code == 200
    with zipfile.ZipFile(io.BytesIO(second_response.data), 'r') as zip_log_file:
        zip_file_list = zip_log_file.namelist()
        with zip_log_file.open(zip_file_list[0]) as extracted_file:
            decoded_log_data = extracted_file.read().decode('utf-8')

    assert decoded_log_data == log_content
    downloaded_expected_path = f"{edl.LOGS_ZIP_FILE_PREFIX}_{datetime.now().strftime('%Y%m%d-%H%M%S')}.zip"
    assert os.path.exists(downloaded_expected_path)
    os.remove(downloaded_expected_path)


@pytest.mark.parametrize(argnames='wip_exist', argvalues=[True, False])
def test_store_log_data(mocker, wip_exist):
    """
    Given:
        - previous log file exist/missing.
    When:
        - call to store_log_data.
    Then:
        - ensure full_log will create only if previous log exist
    """
    import EDL as edl
    from pathlib import Path
    from datetime import datetime
    tmp_dir = mkdtemp()
    wip_log_file = Path(tmp_dir) / 'wip_log_file'
    full_log_file = Path(tmp_dir) / 'full_log_file'

    if wip_exist:
        wip_log_file.write_text('')
        mocker.patch.object(edl, 'EDL_FULL_LOG_PATH_WIP', new=wip_log_file.absolute())

    mocker.patch.object(edl, 'EDL_FULL_LOG_PATH', new=full_log_file.absolute())
    request_args = edl.RequestArguments()
    edl.store_log_data(request_args, datetime.now(), {})
    assert Path(edl.EDL_FULL_LOG_PATH).exists() == wip_exist
