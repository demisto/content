"""Imports"""
import json
import pytest
import demistomock as demisto
from netaddr import IPAddress

IOC_RES_LEN = 38

'''Tests'''


class TestHelperFunctions:
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

    def test_list_to_str_1(self):
        """Test invalid"""
        from ExportIndicators import list_to_str
        with pytest.raises(AttributeError):
            invalid_list_value = 2
            list_to_str(invalid_list_value)

        with pytest.raises(AttributeError):
            invalid_list_value = {'invalid': 'invalid'}
            list_to_str(invalid_list_value)

    def test_list_to_str_2(self):
        """Test empty"""
        from ExportIndicators import list_to_str
        assert list_to_str(None) == ''
        assert list_to_str([]) == ''
        assert list_to_str({}) == ''

    def test_list_to_str_3(self):
        """Test non empty fields"""
        from ExportIndicators import list_to_str
        valid_list_value = [1, 2, 3, 4]
        assert list_to_str(valid_list_value) == '1,2,3,4'
        assert list_to_str(valid_list_value, '.') == '1.2.3.4'
        assert list_to_str(valid_list_value, map_func=lambda x: f'{x}a') == '1a,2a,3a,4a'

    def test_get_params_port_1(self):
        """Test invalid"""
        from CommonServerPython import DemistoException
        from ExportIndicators import get_params_port
        params = {'longRunningPort': 'invalid'}
        with pytest.raises(DemistoException):
            get_params_port(params)

    def test_get_params_port_2(self):
        """Test empty"""
        from ExportIndicators import get_params_port
        params = {'longRunningPort': ''}
        with pytest.raises(ValueError):
            get_params_port(params)

    def test_get_params_port_3(self):
        """Test valid"""
        from ExportIndicators import get_params_port
        params = {'longRunningPort': '80'}
        assert get_params_port(params) == 80

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

    def test_refresh_outbound_context_2(self, mocker):
        """Test out_format= XSOAR json"""
        import ExportIndicators as ei
        with open('ExportIndicators_test/TestHelperFunctions/demisto_iocs.json', 'r') as iocs_json_f:
            iocs_json = json.loads(iocs_json_f.read())
            iocs_json_result = {'iocs': iocs_json, 'total': 100}
            mocker.patch.object(demisto, 'searchIndicators', return_value=iocs_json_result)
            request_args = ei.RequestArguments(query='', out_format='XSOAR json', limit=39)
            ei_vals = ei.refresh_outbound_context(request_args)
            assert isinstance(ei_vals, str)
            ei_vals = json.loads(ei_vals)
            assert iocs_json == ei_vals

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

    def test_refresh_outbound_context_4(self, mocker):
        """Test out_format=XSOAR json-seq"""
        import ExportIndicators as ei
        with open('ExportIndicators_test/TestHelperFunctions/demisto_iocs.json', 'r') as iocs_json_f:
            iocs_json = json.loads(iocs_json_f.read())
            iocs_json_result = {'iocs': iocs_json, 'total': 100}
            mocker.patch.object(demisto, 'searchIndicators', return_value=iocs_json_result)
            request_args = ei.RequestArguments(query='', out_format='XSOAR json-seq', limit=38)
            ei_vals = ei.refresh_outbound_context(request_args)
            with open('ExportIndicators_test/TestHelperFunctions/iocs_out_json_seq.txt', 'r') as iocs_out_f:
                iocs_out = iocs_out_f.read()
                assert iocs_out == ei_vals

    def test_refresh_outbound_context_5(self, mocker):
        """Test out_format=json"""
        import ExportIndicators as ei
        with open('ExportIndicators_test/TestHelperFunctions/demisto_url_iocs.json', 'r') as iocs_json_f:
            iocs_json = json.loads(iocs_json_f.read())
            iocs_json_result = {'iocs': iocs_json, 'total': 100}
            mocker.patch.object(demisto, 'searchIndicators', return_value=iocs_json_result)
            request_args = ei.RequestArguments(query='', out_format='json', limit=2)
            ei_vals = ei.refresh_outbound_context(request_args)
            ei_vals = json.loads(ei_vals)
            with open('ExportIndicators_test/TestHelperFunctions/iocs_out_json.json', 'r') as iocs_json_out_f:
                iocs_json_out = json.loads(iocs_json_out_f.read())
                assert iocs_json_out == ei_vals

    def test_refresh_outbound_context_6(self, mocker):
        """Test out_format=json-seq"""
        import ExportIndicators as ei
        with open('ExportIndicators_test/TestHelperFunctions/demisto_iocs.json', 'r') as iocs_json_f:
            iocs_json = json.loads(iocs_json_f.read())
            iocs_json_result = {'iocs': iocs_json, 'total': 100}
            mocker.patch.object(demisto, 'searchIndicators', return_value=iocs_json_result)
            request_args = ei.RequestArguments(query='', out_format='json-seq', limit=38)
            ei_vals = ei.refresh_outbound_context(request_args)
            with open('ExportIndicators_test/TestHelperFunctions/iocs_out_json_seq_old.txt', 'r') as iocs_out_f:
                iocs_out = iocs_out_f.read()
                for iocs_out_line in iocs_out.split('\n'):
                    assert iocs_out_line in ei_vals

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

    def test_find_indicators_with_limit_1(self, mocker):
        """Test find indicators limit"""
        import ExportIndicators as ei
        with open('ExportIndicators_test/TestHelperFunctions/demisto_iocs.json', 'r') as iocs_json_f:
            iocs_json = json.loads(iocs_json_f.read())
            limit = 30
            indicator_searcher_res = [{'iocs': iocs_json[:limit]}, {'iocs': []}]
            indicator_searcher = ei.IndicatorsSearcher(
                limit=limit
            )
            mocker.patch.object(indicator_searcher, 'search_indicators_by_version', side_effect=indicator_searcher_res)
            ei_vals = ei.find_indicators_with_limit(indicator_searcher)
            assert len(ei_vals) == limit

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

    def test_create_values_for_returned_dict_2(self):
        """Test XSOAR JSON out"""
        from ExportIndicators import create_values_for_returned_dict, FORMAT_XSOAR_JSON, CTX_VALUES_KEY, \
            RequestArguments
        with open('ExportIndicators_test/TestHelperFunctions/demisto_iocs.json', 'r') as iocs_json_f:
            iocs_json = json.load(iocs_json_f)
            request_args = RequestArguments(query='', out_format=FORMAT_XSOAR_JSON)
            returned_dict, _ = create_values_for_returned_dict(iocs_json, request_args)
            json_out = json.loads(returned_dict.get(CTX_VALUES_KEY))
            assert json_out == iocs_json

    def test_create_values_for_returned_dict_3(self):
        """Test XSOAR JSON_SEQ out"""
        from ExportIndicators import create_values_for_returned_dict, FORMAT_XSOAR_JSON_SEQ, CTX_VALUES_KEY, \
            RequestArguments
        with open('ExportIndicators_test/TestHelperFunctions/demisto_iocs.json', 'r') as iocs_json_f:
            iocs_json = json.loads(iocs_json_f.read())
            request_args = RequestArguments(query='', out_format=FORMAT_XSOAR_JSON_SEQ)
            returned_dict, _ = create_values_for_returned_dict(iocs_json, request_args)
            json_seq_out = returned_dict.get(CTX_VALUES_KEY)
            for seq_line in json_seq_out.split('\n'):
                assert json.loads(seq_line) in iocs_json

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
            returned_dict, num_of_indicators = panos_url_formatting(iocs=iocs_json, drop_invalids=True,
                                                                    strip_port=False)
            returned_output = returned_dict.get(CTX_VALUES_KEY)
            assert returned_output == 'www.demisto.com/cool'
            assert num_of_indicators == 1

    def test_create_proxysg_out_format(self):
        from ExportIndicators import create_proxysg_out_format, CTX_VALUES_KEY
        with open('ExportIndicators_test/TestHelperFunctions/demisto_url_iocs.json', 'r') as iocs_json_f:
            iocs_json = json.loads(iocs_json_f.read())

            # classify all categories
            returned_dict, num_of_indicators = create_proxysg_out_format(iocs=iocs_json, category_default="default",
                                                                         category_attribute='')
            returned_output = returned_dict.get(CTX_VALUES_KEY)
            assert returned_output == "define category category2\n1.2.3.4:89/wget\nend\n" \
                                      "define category category1\nwww.demisto.com/cool\nend\n"

            assert num_of_indicators == 2

            # listed category does not exist - all results should be in default category
            returned_dict, num_of_indicators = create_proxysg_out_format(iocs=iocs_json, category_default="default",
                                                                         category_attribute="category3")
            returned_output = returned_dict.get(CTX_VALUES_KEY)
            assert returned_output == "define category default\n1.2.3.4:89/wget\n" \
                                      "www.demisto.com/cool\nend\n"
            assert num_of_indicators == 2

            # list category2 only, the rest go to default
            returned_dict, num_of_indicators = create_proxysg_out_format(iocs=iocs_json, category_default="default",
                                                                         category_attribute="category2")
            returned_output = returned_dict.get(CTX_VALUES_KEY)
            assert returned_output == "define category category2\n1.2.3.4:89/wget\nend\n" \
                                      "define category default\nwww.demisto.com/cool\nend\n"

            assert num_of_indicators == 2

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
            mocker.patch.object(ei, 'find_indicators_with_limit', side_effect=[iocs_json, []])
            request_args = RequestArguments(query='', out_format='text', sort_field=sort_field, sort_order=sort_order)
            ei_vals = refresh_outbound_context(request_args)

            assert ei_vals.split('\n', 1)[0] == expected_first_result

    def test_sort_iocs_with_invalid_order(self, mocker):
        """Test IoCs sorting with invalid order"""
        import ExportIndicators as ei
        from ExportIndicators import refresh_outbound_context, RequestArguments
        with open('ExportIndicators_test/TestHelperFunctions/demisto_iocs.json', 'r') as iocs_json_f:
            iocs_json = json.loads(iocs_json_f.read())
            mocker.patch.object(ei, 'find_indicators_with_limit', side_effect=[iocs_json, []])
            request_args = RequestArguments(query='', out_format='text', sort_field='lastSeen',
                                            sort_order='invalid_sort_order')
            ei_vals = refresh_outbound_context(request_args)

            assert ei_vals.split('\n', 1)[0] == '213.182.138.224'

    def test_sort_iocs_invalid_field(self, mocker):
        """Test IoCs sorting wit invalid field"""
        import ExportIndicators as ei
        from ExportIndicators import refresh_outbound_context, RequestArguments
        with open('ExportIndicators_test/TestHelperFunctions/demisto_iocs.json', 'r') as iocs_json_f:
            iocs_json = json.loads(iocs_json_f.read())
            mocker.patch.object(ei, 'find_indicators_with_limit', side_effect=[iocs_json, []])
            request_args = RequestArguments(query='', out_format='text', sort_field='invalid_field_name',
                                            sort_order='asc')
            mocker.patch.object(demisto, 'debug')
            refresh_outbound_context(request_args)

            debug_list = [call[0][0] for call in demisto.debug.call_args_list]
            assert 'ExportIndicators - Could not sort IoCs, please verify that you entered the correct field name.\n' \
                   'Field used: invalid_field_name' in debug_list
