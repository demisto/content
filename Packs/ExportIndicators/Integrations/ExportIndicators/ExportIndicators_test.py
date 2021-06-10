"""Imports"""
import json
import pytest
import requests
import demistomock as demisto
from netaddr import IPAddress
from pathlib import Path
import os
from pytest_mock import MockerFixture
from time import sleep
import subprocess
from typing import Optional

IOC_RES_LEN = 38

'''Tests'''


@pytest.mark.helper_commands
class TestHelperFunctions:
    @pytest.mark.get_outbound_ioc_values
    def test_get_outbound_ioc_values_1(self, mocker):
        """Test on_demand"""
        from ExportIndicators import get_outbound_ioc_values, RequestArguments
        with open('ExportIndicators_test/TestHelperFunctions/iocs_cache_values_text.json', 'r') as iocs_text_values_f:
            iocs_text_dict = json.loads(iocs_text_values_f.read())
            mocker.patch.object(demisto, 'getIntegrationContext', return_value={"last_output": iocs_text_dict})
            request_args = RequestArguments(query='', out_format='text', limit=50, offset=0)
            ioc_list = get_outbound_ioc_values(
                on_demand=True,
                request_args=request_args
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
            request_args = ei.RequestArguments(query='', out_format='text', limit=50, offset=0)
            ioc_list = ei.get_outbound_ioc_values(
                on_demand=False,
                request_args=request_args,
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
            request_args = ei.RequestArguments(query='', out_format='text', limit=50, offset=0)
            ioc_list = ei.get_outbound_ioc_values(
                on_demand=False,
                request_args=request_args,
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
            request_args = ei.RequestArguments(query='type:ip', out_format='text', limit=50, offset=0)
            ioc_list = ei.get_outbound_ioc_values(
                on_demand=False,
                request_args=request_args,
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
            request_args = ei.RequestArguments(query='type:ip', out_format='text', limit=50, offset=0)
            ioc_list = ei.get_outbound_ioc_values(
                on_demand=False,
                request_args=request_args,
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
            request_args = ei.RequestArguments(query='type:ip', out_format='text', limit=50, offset=0)
            ioc_list = ei.get_outbound_ioc_values(
                on_demand=False,
                request_args=request_args,
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
            request_args = ei.RequestArguments(query='', out_format='text', limit=38)
            ei_vals = ei.refresh_outbound_context(request_args)
            for ioc in iocs_json:
                ip = ioc.get('value')
                if ip:
                    assert ip in ei_vals

    @pytest.mark.refresh_outbound_context
    def test_refresh_outbound_context_2(self, mocker):
        """Test out_format= XSOAR json"""
        import ExportIndicators as ei
        with open('ExportIndicators_test/TestHelperFunctions/demisto_iocs.json', 'r') as iocs_json_f:
            iocs_json = json.loads(iocs_json_f.read())
            mocker.patch.object(ei, 'find_indicators_with_limit', return_value=iocs_json)
            request_args = ei.RequestArguments(query='', out_format='XSOAR json', limit=38)
            ei_vals = ei.refresh_outbound_context(request_args)
            assert isinstance(ei_vals, str)
            ei_vals = json.loads(ei_vals)
            assert iocs_json == ei_vals

    @pytest.mark.refresh_outbound_context
    def test_refresh_outbound_context_3(self, mocker):
        """Test out_format=xsoar-csv"""
        import ExportIndicators as ei
        with open('ExportIndicators_test/TestHelperFunctions/demisto_iocs.json', 'r') as iocs_json_f:
            iocs_json = json.loads(iocs_json_f.read())
            mocker.patch.object(ei, 'find_indicators_with_limit', return_value=iocs_json)
            request_args = ei.RequestArguments(query='', out_format='XSOAR csv', limit=38)
            ei_vals = ei.refresh_outbound_context(request_args)
            with open('ExportIndicators_test/TestHelperFunctions/iocs_out_csv.txt', 'r') as iocs_out_f:
                iocs_out = iocs_out_f.read()
                for ioc in iocs_out.split('\n'):
                    assert ioc in ei_vals

    @pytest.mark.refresh_outbound_context
    def test_refresh_outbound_context_4(self, mocker):
        """Test out_format=XSOAR json-seq"""
        import ExportIndicators as ei
        with open('ExportIndicators_test/TestHelperFunctions/demisto_iocs.json', 'r') as iocs_json_f:
            iocs_json = json.loads(iocs_json_f.read())
            mocker.patch.object(ei, 'find_indicators_with_limit', return_value=iocs_json)
            request_args = ei.RequestArguments(query='', out_format='XSOAR json-seq', limit=38)
            ei_vals = ei.refresh_outbound_context(request_args)
            with open('ExportIndicators_test/TestHelperFunctions/iocs_out_json_seq.txt', 'r') as iocs_out_f:
                iocs_out = iocs_out_f.read()
                assert iocs_out == ei_vals

    @pytest.mark.refresh_outbound_context
    def test_refresh_outbound_context_5(self, mocker):
        """Test out_format=json"""
        import ExportIndicators as ei
        with open('ExportIndicators_test/TestHelperFunctions/demisto_url_iocs.json', 'r') as iocs_json_f:
            iocs_json = json.loads(iocs_json_f.read())
            mocker.patch.object(ei, 'find_indicators_with_limit', return_value=iocs_json)
            request_args = ei.RequestArguments(query='', out_format='json', limit=2)
            ei_vals = ei.refresh_outbound_context(request_args)
            ei_vals = json.loads(ei_vals)
            with open('ExportIndicators_test/TestHelperFunctions/iocs_out_json.json', 'r') as iocs_json_out_f:
                iocs_json_out = json.loads(iocs_json_out_f.read())
                assert iocs_json_out == ei_vals

    @pytest.mark.refresh_outbound_context
    def test_refresh_outbound_context_6(self, mocker):
        """Test out_format=json-seq"""
        import ExportIndicators as ei
        with open('ExportIndicators_test/TestHelperFunctions/demisto_iocs.json', 'r') as iocs_json_f:
            iocs_json = json.loads(iocs_json_f.read())
            mocker.patch.object(ei, 'find_indicators_with_limit', return_value=iocs_json)
            request_args = ei.RequestArguments(query='', out_format='json-seq', limit=38)
            ei_vals = ei.refresh_outbound_context(request_args)
            with open('ExportIndicators_test/TestHelperFunctions/iocs_out_json_seq_old.txt', 'r') as iocs_out_f:
                iocs_out = iocs_out_f.read()
                for iocs_out_line in iocs_out.split('\n'):
                    assert iocs_out_line in ei_vals

    @pytest.mark.refresh_outbound_context
    def test_refresh_outbound_context_7(self, mocker):
        """Test out_format=csv"""
        import ExportIndicators as ei
        with open('ExportIndicators_test/TestHelperFunctions/demisto_iocs.json', 'r') as iocs_json_f:
            iocs_json = json.loads(iocs_json_f.read())
            mocker.patch.object(ei, 'find_indicators_with_limit', return_value=iocs_json)
            request_args = ei.RequestArguments(query='', out_format='csv', limit=38)
            ei_vals = ei.refresh_outbound_context(request_args)
            with open('ExportIndicators_test/TestHelperFunctions/iocs_out_csv_old.txt', 'r') as iocs_out_f:
                iocs_out = iocs_out_f.read()
                for ioc in iocs_out.split('\n'):
                    assert ioc in ei_vals

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
        """Test XSOAR CSV out"""
        from ExportIndicators import create_values_for_returned_dict, FORMAT_XSOAR_CSV, RequestArguments, CTX_VALUES_KEY
        with open('ExportIndicators_test/TestHelperFunctions/demisto_iocs.json', 'r') as iocs_json_f:
            iocs_json = json.loads(iocs_json_f.read())
            request_args = RequestArguments(query='', out_format=FORMAT_XSOAR_CSV)
            returned_dict, _ = create_values_for_returned_dict(iocs_json, request_args)
            csv_out = returned_dict.get(CTX_VALUES_KEY)
            # assert len(csv_out) == IOC_RES_LEN + 1
            with open('ExportIndicators_test/TestHelperFunctions/iocs_out_csv.txt', 'r') as iocs_out_f:
                expected_csv_out = iocs_out_f.read()
                for csv_line in csv_out.split('\n'):
                    assert csv_line in expected_csv_out

    @pytest.mark.create_values_for_returned_dict
    def test_create_values_for_returned_dict_2(self):
        """Test XSOAR JSON out"""
        from ExportIndicators import create_values_for_returned_dict, FORMAT_XSOAR_JSON, CTX_VALUES_KEY, RequestArguments
        with open('ExportIndicators_test/TestHelperFunctions/demisto_iocs.json', 'r') as iocs_json_f:
            iocs_json = json.load(iocs_json_f)
            request_args = RequestArguments(query='', out_format=FORMAT_XSOAR_JSON)
            returned_dict, _ = create_values_for_returned_dict(iocs_json, request_args)
            json_out = json.loads(returned_dict.get(CTX_VALUES_KEY))
            assert json_out == iocs_json

    @pytest.mark.create_values_for_returned_dict
    def test_create_values_for_returned_dict_3(self):
        """Test XSOAR JSON_SEQ out"""
        from ExportIndicators import create_values_for_returned_dict, FORMAT_XSOAR_JSON_SEQ, CTX_VALUES_KEY, RequestArguments
        with open('ExportIndicators_test/TestHelperFunctions/demisto_iocs.json', 'r') as iocs_json_f:
            iocs_json = json.loads(iocs_json_f.read())
            request_args = RequestArguments(query='', out_format=FORMAT_XSOAR_JSON_SEQ)
            returned_dict, _ = create_values_for_returned_dict(iocs_json, request_args)
            json_seq_out = returned_dict.get(CTX_VALUES_KEY)
            for seq_line in json_seq_out.split('\n'):
                assert json.loads(seq_line) in iocs_json

    @pytest.mark.create_values_for_returned_dict
    def test_create_values_for_returned_dict_4(self):
        """Test TEXT out"""
        from ExportIndicators import create_values_for_returned_dict, FORMAT_TEXT, CTX_VALUES_KEY, RequestArguments
        with open('ExportIndicators_test/TestHelperFunctions/demisto_iocs.json', 'r') as iocs_json_f:
            iocs_json = json.loads(iocs_json_f.read())
            request_args = RequestArguments(query='', out_format=FORMAT_TEXT)
            returned_dict, _ = create_values_for_returned_dict(iocs_json, request_args)
            text_out = returned_dict.get(CTX_VALUES_KEY)
            with open('ExportIndicators_test/TestHelperFunctions/iocs_cache_values_text.json', 'r') as iocs_txt_f:
                iocs_txt_json = json.load(iocs_txt_f)
                for line in text_out.split('\n'):
                    assert line in iocs_txt_json

    @pytest.mark.create_values_out_dict
    def test_create_values_for_returned_dict_5(self):
        """Test JSON out"""
        from ExportIndicators import create_values_for_returned_dict, FORMAT_JSON, CTX_VALUES_KEY, RequestArguments
        with open('ExportIndicators_test/TestHelperFunctions/demisto_url_iocs.json', 'r') as iocs_json_f:
            iocs_json = json.loads(iocs_json_f.read())
            request_args = RequestArguments(query='', out_format=FORMAT_JSON)
            returned_dict, _ = create_values_for_returned_dict(iocs_json, request_args)
            json_out = json.loads(returned_dict.get(CTX_VALUES_KEY))
            with open('ExportIndicators_test/TestHelperFunctions/iocs_out_json.json', 'r') as iocs_json_out_f:
                iocs_json_out = json.loads(iocs_json_out_f.read())
                assert iocs_json_out == json_out

    @pytest.mark.create_values_out_dict
    def test_create_values_for_returned_dict_6(self):
        """Test JSON_SEQ out"""
        from ExportIndicators import create_values_for_returned_dict, FORMAT_JSON_SEQ, CTX_VALUES_KEY, RequestArguments
        with open('ExportIndicators_test/TestHelperFunctions/demisto_url_iocs.json', 'r') as iocs_json_f:
            iocs_json = json.loads(iocs_json_f.read())
            request_args = RequestArguments(query='', out_format=FORMAT_JSON_SEQ)
            returned_dict, _ = create_values_for_returned_dict(iocs_json, request_args)
            json_seq_out = returned_dict.get(CTX_VALUES_KEY)
            with open('ExportIndicators_test/TestHelperFunctions/iocs_out_json.json', 'r') as iocs_json_out_f:
                iocs_json_out = json.load(iocs_json_out_f)
                for seq_line in json_seq_out.split('\n'):
                    assert json.loads(seq_line) in iocs_json_out

    @pytest.mark.create_values_out_dict
    def test_create_values_for_returned_dict_7(self):
        """Test CSV out"""
        from ExportIndicators import create_values_for_returned_dict, FORMAT_CSV, RequestArguments, CTX_VALUES_KEY
        with open('ExportIndicators_test/TestHelperFunctions/demisto_iocs.json', 'r') as iocs_json_f:
            iocs_json = json.loads(iocs_json_f.read())
            request_args = RequestArguments(query='', out_format=FORMAT_CSV)
            returned_dict, _ = create_values_for_returned_dict(iocs_json, request_args)
            csv_out = returned_dict.get(CTX_VALUES_KEY)
            # assert len(csv_out) == IOC_RES_LEN + 1
            with open('ExportIndicators_test/TestHelperFunctions/iocs_out_csv_old.txt', 'r') as iocs_out_f:
                expected_csv_out = iocs_out_f.read()
                for csv_lint in csv_out.split('\n'):
                    assert csv_lint in expected_csv_out

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

    @pytest.mark.validate_basic_authentication
    def test_panos_url_formatting(self):
        from ExportIndicators import panos_url_formatting, CTX_VALUES_KEY
        with open('ExportIndicators_test/TestHelperFunctions/demisto_url_iocs.json', 'r') as iocs_json_f:
            iocs_json = json.loads(iocs_json_f.read())

            # strips port numbers
            returned_dict, num_of_indicators = panos_url_formatting(iocs=iocs_json, drop_invalids=True, strip_port=True)
            returned_output = returned_dict.get(CTX_VALUES_KEY)
            assert returned_output == "1.2.3.4/wget\nwww.demisto.com/cool"
            assert num_of_indicators == 2

            # should ignore indicators with port numbers
            returned_dict, num_of_indicators = panos_url_formatting(iocs=iocs_json, drop_invalids=True, strip_port=False)
            returned_output = returned_dict.get(CTX_VALUES_KEY)
            assert returned_output == 'www.demisto.com/cool'
            assert num_of_indicators == 1

    @pytest.mark.validate_basic_authentication
    def test_create_proxysg_out_format(self):
        from ExportIndicators import create_proxysg_out_format, CTX_VALUES_KEY
        with open('ExportIndicators_test/TestHelperFunctions/demisto_url_iocs.json', 'r') as iocs_json_f:
            iocs_json = json.loads(iocs_json_f.read())

            # classify all categories
            returned_dict, num_of_indicators = create_proxysg_out_format(iocs=iocs_json, category_default="default",
                                                                         category_attribute='')
            returned_output = returned_dict.get(CTX_VALUES_KEY)
            assert returned_output == "define category category2\n1.2.3.4:89/wget\nend\n" \
                                      "define category category1\nhttps://www.demisto.com/cool\nend\n"

            assert num_of_indicators == 2

            # listed category does not exist - all results should be in default category
            returned_dict, num_of_indicators = create_proxysg_out_format(iocs=iocs_json, category_default="default",
                                                                         category_attribute="category3")
            returned_output = returned_dict.get(CTX_VALUES_KEY)
            assert returned_output == "define category default\n1.2.3.4:89/wget\n" \
                                      "https://www.demisto.com/cool\nend\n"
            assert num_of_indicators == 2

            # list category2 only, the rest go to default
            returned_dict, num_of_indicators = create_proxysg_out_format(iocs=iocs_json, category_default="default",
                                                                         category_attribute="category2")
            returned_output = returned_dict.get(CTX_VALUES_KEY)
            assert returned_output == "define category category2\n1.2.3.4:89/wget\nend\n" \
                                      "define category default\nhttps://www.demisto.com/cool\nend\n"

            assert num_of_indicators == 2

    @pytest.mark.validate_basic_authentication
    def test_create_mwg_out_format(self):
        from ExportIndicators import create_mwg_out_format, CTX_VALUES_KEY
        with open('ExportIndicators_test/TestHelperFunctions/demisto_url_iocs.json', 'r') as iocs_json_f:
            iocs_json = json.loads(iocs_json_f.read())

            # listed category does not exist - all results should be in default category
            returned_dict = create_mwg_out_format(iocs=iocs_json, mwg_type="ip")
            returned_output = returned_dict.get(CTX_VALUES_KEY)

            assert returned_output == "type=ip\n\"1.2.3.4:89/wget\" \"AutoFocus Feed\"\n\"" \
                                      "https://www.demisto.com/cool\" \"AutoFocus V2,VirusTotal," \
                                      "Alien Vault OTX TAXII Feed\""

    @pytest.mark.validate_basic_authentication
    def test_create_json_out_format(self):
        from ExportIndicators import create_json_out_format, CTX_VALUES_KEY
        with open('ExportIndicators_test/TestHelperFunctions/demisto_url_iocs.json', 'r') as iocs_json_f:
            iocs_json = json.loads(iocs_json_f.read())

            # listed category does not exist - all results should be in default category
            returned_dict = create_json_out_format(iocs=iocs_json)
            returned_output = json.loads(returned_dict.get(CTX_VALUES_KEY))

            assert returned_output[0].get('indicator') == '1.2.3.4:89/wget'
            assert isinstance(returned_output[0].get('value'), dict)

            assert returned_output[1].get('indicator') == 'https://www.demisto.com/cool'
            assert isinstance(returned_output[1].get('value'), dict)

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
        assert "25.24.23.22" in ip_range_list

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
        assert "25.24.23.22" in ip_range_list

    def test_empty_integartion_context_mimtype(self, mocker):
        from ExportIndicators import get_outbound_mimetype
        mocker.patch.object(demisto, 'getIntegrationContext', return_value={})
        mimtype = get_outbound_mimetype()
        assert mimtype == 'text/plain'

    @pytest.mark.parametrize('sort_field, sort_order, expected_first_result', [
        ('lastSeen', 'asc', '200.77.186.170'),
        ('lastSeen', 'desc', '188.166.23.215'),
    ])
    def test_sort_iocs(self, mocker, sort_field, sort_order, expected_first_result):
        """Test IoCs sorting"""
        import ExportIndicators as ei
        from ExportIndicators import refresh_outbound_context, RequestArguments
        with open('ExportIndicators_test/TestHelperFunctions/demisto_iocs.json', 'r') as iocs_json_f:
            iocs_json = json.loads(iocs_json_f.read())
            mocker.patch.object(ei, 'find_indicators_with_limit', return_value=iocs_json)
            request_args = RequestArguments(query='', out_format='text', sort_field=sort_field, sort_order=sort_order)
            ei_vals = refresh_outbound_context(request_args)

            assert ei_vals.split('\n', 1)[0] == expected_first_result

    def test_sort_iocs_with_invalid_order(self, mocker):
        """Test IoCs sorting with invalid order"""
        import ExportIndicators as ei
        from ExportIndicators import refresh_outbound_context, RequestArguments
        with open('ExportIndicators_test/TestHelperFunctions/demisto_iocs.json', 'r') as iocs_json_f:
            iocs_json = json.loads(iocs_json_f.read())
            mocker.patch.object(ei, 'find_indicators_with_limit', return_value=iocs_json)
            request_args = RequestArguments(query='', out_format='text', sort_field='lastSeen', sort_order='invalid_sort_order')
            ei_vals = refresh_outbound_context(request_args)

            assert ei_vals.split('\n', 1)[0] == '213.182.138.224'

    def test_sort_iocs_invalid_field(self, mocker):
        """Test IoCs sorting wit invalid field"""
        import ExportIndicators as ei
        from ExportIndicators import refresh_outbound_context, RequestArguments
        with open('ExportIndicators_test/TestHelperFunctions/demisto_iocs.json', 'r') as iocs_json_f:
            iocs_json = json.loads(iocs_json_f.read())
            mocker.patch.object(ei, 'find_indicators_with_limit', return_value=iocs_json)
            request_args = RequestArguments(query='', out_format='text', sort_field='invalid_field_name', sort_order='asc')
            mocker.patch.object(demisto, 'debug')
            refresh_outbound_context(request_args)

            debug_list = [call[0][0] for call in demisto.debug.call_args_list]
            assert 'ExportIndicators - Could not sort IoCs, please verify that you entered the correct field name.\n' \
                   'Field used: invalid_field_name' in debug_list


SSL_TEST_KEY = '''-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDd5FcvCKgtXjkY
aiDdqpFAYKw6WxNEpZIGjzD9KhEqr7OZjpPoLeyGh1U6faAcN6XpkQugFA/2Gq+Z
j/pe1abiTCbctdE978FYVjXxbEEAtEn4x28s/bKah/xjjw+RjUyQB9DsioFkV1eN
9iJh5eOOIOjTDMBt7SxY1HivC0HjUKjCaMjdH2WxGu4na9phPOa7zixlgLqZGC8g
E1Ati5j3nOEOlmrNIf1Z/4zdJzEaMprBCymfEvrgMC7ibG9AokDcAj6Sl4xgvTRp
tTczCbUxF1jsnNNbuLyq/RuQ85SWB3mrRKT4OgPtz/ga3sm4l7Uq/YN71Gr/Lxaq
bkwWVMd/AgMBAAECggEBAKnMfacBYejtzJVRSXs3dlWkZMd3QGRsqzUXyG5DDcXz
lGVyxN6Mng5Ia8EJt0dAklcM5q+GCrzSqQPDON3vcviDO83z2H4kBXm65yarJ4cJ
b/3PZ9UvAsjcPRhWtpw0W51wTcFlMCT/7YE2FBOEX0E5D9HJVUwJjcEgPoX9AFuY
xYVpFvr1AoORde/RoJGoe+Z81hIRvcbrzfLHEMCB0pY0wxBuD5tyhEunIwLxG+6v
T1OHtuXDATEGabZQJKuhBfuP00YFRKxHIBLWPtkplQGFAXmBEeD5NIYfo+RBQFUH
GuvDTHoEvecn9ZHF4eOjJ88TXaGuXrFHwa0g0KMDNaECgYEA+ld2bkC4RXNWIzYI
4bOH7UBFrd74nz4zqNd2UZqP9R1al8nLgcESiT6izBbR+6wnNANIon5fXYGFK+wu
NGvKwuL1Xf04Ro/Z/i03QrV5fTgL/F8NX9F0kc6znxli9SrpswSjb1ZUoJmQXCew
ZYkCVavy3Zpgk8uHeeaHOOAI6k8CgYEA4uhC2Jy9Ysq6Eg79hVq0xHtXLl0VWfrU
5mugItrH90LmsCvKK4Qzg33BjhIMbE9vq63yFxW08845weuxUV6LalPSLOclE7D2
6exG5grcdGpqyWKc2qCAXP2uLys68cOfWduJoVUYsdAGbyNdvkI69VcTsI8pV6kR
bjzP+l50c9ECgYA3CVN4GbJpUln1k8OQGzAe8Kpg90whdkNVM0lH13seoD1ycWLU
O+YfVi3kQIAZnFdiD/bAAphkrjzg0yO1Up1ZCxx2dV0R5j4+qyIjAFKdPN0ltp/y
GNJP2+mRaLtguvZ17OchaxFf3WLnX7JgICbrPso9/dqNo4k9O3ku/9H18QKBgQDZ
LaMlfsgJ8a2ssSpYZBwW31LvbmqMR/dUX/jSw4KXmDICtrb3db50gX4rw/yeAl4I
/SF0lPMwU9eWU0fRcOORro7BKa+kLEH4XYzyi7y7tEtnW3p0CyExYCFCxmbRlgJE
WEtf3noXXtt5rmkAPJX/0wtmd3ADli+3yn7pzVQ6sQKBgQDJJITERtov019Cwuux
fCRUIbRyUH/PCN/VvsuKFs+BWbFTnqBXRDQetzTyuUvNKiL7GmWQuR/QpgYjLd9W
jxAayhtcVKeL96dqimK9twmw/NC5DveOVoReXx7io4gicmQi7AGq5WRkm8NUZRVE
1dH1Hhp7kjnPlUOUBvKf8mfFxQ==
-----END PRIVATE KEY-----
'''

SSL_TEST_CRT = '''-----BEGIN CERTIFICATE-----
MIIDeTCCAmGgAwIBAgIUaam3vV40bjLs7mabludFi6dRsxkwDQYJKoZIhvcNAQEL
BQAwTDELMAkGA1UEBhMCSUwxEzARBgNVBAgMClNvbWUtU3RhdGUxEzARBgNVBAoM
ClhTT0FSIFRlc3QxEzARBgNVBAMMCnhzb2FyLXRlc3QwHhcNMjEwNTE2MTQzNDU0
WhcNMzAwODAyMTQzNDU0WjBMMQswCQYDVQQGEwJJTDETMBEGA1UECAwKU29tZS1T
dGF0ZTETMBEGA1UECgwKWFNPQVIgVGVzdDETMBEGA1UEAwwKeHNvYXItdGVzdDCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAN3kVy8IqC1eORhqIN2qkUBg
rDpbE0SlkgaPMP0qESqvs5mOk+gt7IaHVTp9oBw3pemRC6AUD/Yar5mP+l7VpuJM
Jty10T3vwVhWNfFsQQC0SfjHbyz9spqH/GOPD5GNTJAH0OyKgWRXV432ImHl444g
6NMMwG3tLFjUeK8LQeNQqMJoyN0fZbEa7idr2mE85rvOLGWAupkYLyATUC2LmPec
4Q6Was0h/Vn/jN0nMRoymsELKZ8S+uAwLuJsb0CiQNwCPpKXjGC9NGm1NzMJtTEX
WOyc01u4vKr9G5DzlJYHeatEpPg6A+3P+BreybiXtSr9g3vUav8vFqpuTBZUx38C
AwEAAaNTMFEwHQYDVR0OBBYEFJLT/bq2cGAu6buAQSoeusx439YaMB8GA1UdIwQY
MBaAFJLT/bq2cGAu6buAQSoeusx439YaMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZI
hvcNAQELBQADggEBACmcsfDI382F64TWtJaEn4pKCTjiJloXfb3curr7qYVfeLUX
jbb6aRha88/PB+6/IC/lR0JjXRWMMQafFFR7rb1290p2YVPE9T5Wc5934M590LxZ
bwa5YsCF+qzBiWPMUs5s/el8AHTnUQdU/CKLMI7ZL2IpyTpfW4PERw2HiOBdgCbl
1DzjH9L1bmCzIhXBR6bUXUn4vjg8VBIQ29uHrLNN1fgDyRB1eAaOs4iuBAZm7IkC
k+cVw239GwbLsYkRg5BpkQF4IC6a4+Iz9fpvpUc/g6jpxtGU0kE2DVWOEAyPOOWC
C/t/GFcoOUze68WuI/BqMAiWhPJ1ioL7RI2ZPvI=
-----END CERTIFICATE-----
'''


def test_nginx_conf(tmp_path: Path):
    from ExportIndicators import create_nginx_server_conf
    conf_file = str(tmp_path / "nginx-test-server.conf")
    create_nginx_server_conf(conf_file, 12345, params={})
    with open(conf_file, 'rt') as f:
        conf = f.read()
        assert 'listen 12345 default_server' in conf


NGINX_PROCESS: Optional[subprocess.Popen] = None


@pytest.fixture
def nginx_cleanup():
    yield
    from ExportIndicators import NGINX_SERVER_CONF_FILE
    Path(NGINX_SERVER_CONF_FILE).unlink(missing_ok=True)
    global NGINX_PROCESS
    if NGINX_PROCESS:
        NGINX_PROCESS.terminate()
        # let the process terminate
        NGINX_PROCESS.wait(1.0)
        NGINX_PROCESS = None


docker_only = pytest.mark.skipif('flask-nginx' not in os.getenv('DOCKER_IMAGE', ''), reason='test should run only within docker')


@docker_only
def test_nginx_start_fail(mocker: MockerFixture, nginx_cleanup):
    """Test that nginx fails when config is invalid
    """
    def nginx_bad_conf(file_path: str, port: int, params: dict):
        with open(file_path, 'wt') as f:
            f.write('server {bad_stuff test;}')
    import ExportIndicators as edl
    mocker.patch.object(edl, 'create_nginx_server_conf', side_effect=nginx_bad_conf)
    try:
        edl.start_nginx_server(12345, {})
        pytest.fail('nginx start should fail')
    except ValueError as e:
        assert 'bad_stuff' in str(e)


@docker_only
def test_nginx_start_fail_directive(nginx_cleanup):
    """Test that nginx fails when invalid global directive is passed
    """
    import ExportIndicators as edl
    try:
        edl.start_nginx_server(12345, {'nginx_global_directives': 'bad_directive test;'})
        pytest.fail('nginx start should fail')
    except ValueError as e:
        assert 'bad_directive' in str(e)


@docker_only
@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
@pytest.mark.parametrize('params', [
    {},
    {'certificate': SSL_TEST_CRT, 'key': SSL_TEST_KEY},
])
def test_nginx_test_start_valid(nginx_cleanup, params):
    import ExportIndicators as edl
    edl.test_nginx_server(11300, params)
    # check that nginx process is not up
    sleep(0.5)
    ps_out = subprocess.check_output(['ps', 'aux'], text=True)
    assert 'nginx' not in ps_out


@docker_only
def test_nginx_log_process(nginx_cleanup, mocker: MockerFixture):
    import ExportIndicators as edl
    # clear logs for test
    Path(edl.NGINX_SERVER_ACCESS_LOG).unlink(missing_ok=True)
    Path(edl.NGINX_SERVER_ERROR_LOG).unlink(missing_ok=True)
    NGINX_PROCESS = edl.start_nginx_server(12345, {})
    sleep(0.5)  # give nginx time to start
    # create a request to get a log line
    requests.get('http://localhost:12345/nginx-test?unit_testing')
    sleep(0.2)
    mocker.patch.object(demisto, 'info')
    mocker.patch.object(demisto, 'error')
    edl.nginx_log_process(NGINX_PROCESS)
    # call_args is tuple (args list, kwargs). we only need the args
    arg = demisto.info.call_args[0][0]
    assert 'nginx access log' in arg
    assert 'unit_testing' in arg
    arg = demisto.error.call_args[0][0]
    assert '[warn]' in arg
    assert 'the master process runs with super-user privileges' in arg
    # make sure old file was removed
    assert not Path(edl.NGINX_SERVER_ACCESS_LOG + '.old').exists()
    assert not Path(edl.NGINX_SERVER_ERROR_LOG + '.old').exists()
    # make sure log was rolled over files should be of size 0
    assert not Path(edl.NGINX_SERVER_ACCESS_LOG).stat().st_size
    assert not Path(edl.NGINX_SERVER_ERROR_LOG).stat().st_size
