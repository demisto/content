import tempfile
from unittest.mock import patch

from unittest.mock import MagicMock

from XDR_iocs import *
import pytest
from freezegun import freeze_time


Client.severity = 'INFO'
client = Client({'url': 'https://example.com'})


def d_sort(in_dict):
    return sorted(in_dict.items())


class TestGetHeaders:
    @freeze_time('2020-06-01T00:00:00Z')
    def test_sanity(self, mocker):
        """
            Given:
             - API key
             - API key ID
            Then:
                - Verify headers created correct.
        """
        params = {
            "apikey_id": "7",
            "apikey": "aaaaaaa"
            # noqa: E501
        }
        headers = {
            'Authorization': 'e9a63fb06148bd3a73ce93c8b44c083a147cafb0fe607e706abcac25759b3c43',  # it's a dummy Authorization
            'x-iocs-source': 'xsoar',
            'x-xdr-auth-id': '7',
            'x-xdr-nonce': '1111111111111111111111111111111111111111111111111111111111111111',
            'x-xdr-timestamp': '1590969600000'
        }
        mocker.patch('secrets.choice', return_value='1')
        output = get_headers(params)
        assert output == headers, f'get_headers({params})\n\treturns: {d_sort(output)}\n\tinstead: {d_sort(headers)}'

    def test_empty_case(self):
        """
            Given:
                Empty params
            Then:
                get_headers will not raise error
        """
        get_headers({})


class TestHttpRequest:
    def test_http_request_ok(self, requests_mock):
        """
            Given:
                - a client
            When:
                - http_request returns status code 200.
            Then:
                - do not raise an error
        """
        requests_mock.post('https://example.com/public_api/v1/indicators/suffix', status_code=200, json={})
        client.http_request(url_suffix='suffix', requests_kwargs={})

    @pytest.mark.parametrize('status_code', client.error_codes.keys())
    def test_http_request_error(self, requests_mock, status_code):
        """
            Given:
                - Status code
            When:
                - http_request returns this status code.
            Then:
                - Verify error message.
                - Verify exception.res status code matches the http status code.
        """
        with pytest.raises(DemistoException) as e:
            requests_mock.post('https://example.com/public_api/v1/indicators/suffix', status_code=status_code)
            client.http_request('suffix', requests_kwargs={})
        assert e.value.message == client.error_codes[status_code]
        assert e.value.res.status_code == status_code

    def test_http_request_bad_json(self, requests_mock):
        # For an unknown reason, this does not pass locally, but only on the CI.
        """
            Given:
                - a client
            When:
                - http_request returns a response that is not a json.
            Then:
                - Verify error message.
                - Verify demisto exception
        """
        text = 'not a json'

        with pytest.raises(DemistoException) as e:
            requests_mock.post('https://example.com/public_api/v1/indicators/suffix', status_code=200, text=text)
            client.http_request('suffix', requests_kwargs={})
        assert e.value.message == f'Could not parse json out of {text}'
        assert e.value.res.status_code == 200
        assert isinstance(e.value.exception, requests.exceptions.JSONDecodeError | json.decoder.JSONDecodeError)


class TestGetRequestsKwargs:

    def test_with_file(self, mocker):
        """
            Given:
                - file to upload
            Then:
                - Verify output format.
        """
        def override_open(open_path, *_other):
            return open_path

        mocker.patch('builtins.open', side_effect=override_open)
        path = '/Users/some_user/some_dir/some_file.file'
        output = get_requests_kwargs(file_path=path)
        expected_output = {'files': [('file', ('iocs.json', path, 'application/json'))]}
        assert output == expected_output, f'get_requests_kwargs(file_path={path})\n\treturns: {output}\n\t instead: {expected_output}'  # noqa: E501

    def test_with_json(self):
        """
            Given:
                - simple json
            Then:
                - the json ready to send
        """
        _json = {'test': 'test'}
        output = get_requests_kwargs(_json=_json)
        expected_output = {'data': '{"request_data": {"test": "test"}}'}
        assert output == expected_output, f'get_requests_kwargs(_json={_json})\n\treturns: {output}\n\t instead: {expected_output}'     # noqa: E501


class TestPrepareCommands:

    @freeze_time('2022-04-14T00:00:00Z')
    def test_prepare_get_changes(self):
        """
            Given:
                - get changes command
            Then:
                - Verify url and json format.
        """

        ts = int(datetime.now(timezone.utc).timestamp() * 1000)
        url_suffix, _json = prepare_get_changes(ts)
        assert url_suffix == 'get_changes', f'prepare_get_changes\n\treturns url_suffix: {url_suffix}\n\tinstead url_suffix: get_changes'   # noqa: E501
        assert _json == {'last_update_ts': ts}

    def test_prepare_enable_iocs(self):
        """
            Given:
                - enable iocs command
            Then:
                - Verify url and json format.
        """
        url_suffix, iocs = prepare_enable_iocs('8.8.8.8,domain.com')
        assert url_suffix == 'enable_iocs', f'prepare_enable_iocs\n\treturns url_suffix: {url_suffix}\n\tinstead url_suffix: enable_iocs'   # noqa: E501
        assert iocs == ['8.8.8.8', 'domain.com']

    def test_prepare_disable_iocs(self):
        """
            Given:
                - disable iocs command
            Then:
                - Verify url and json format.
        """
        url_suffix, iocs = prepare_disable_iocs('8.8.8.8,domain.com')
        assert url_suffix == 'disable_iocs', f'prepare_disable_iocs\n\treturns url_suffix: {url_suffix}\n\tinstead url_suffix: disable_iocs'    # noqa: E501
        assert iocs == ['8.8.8.8', 'domain.com']


class TestCreateFile:
    path = 'test_data/sync_file_test.json'
    data_test_create_file_sync = [
        ('Domain_iocs', 'Domain_sync_file'),
        ('IP_iocs', 'IP_sync_file'),
        ('File_iocs', 'File_sync_file')
    ]
    data_test_create_file_iocs_to_keep = [
        ('Domain_iocs', 'Domain_iocs_to_keep_file'),
        ('IP_iocs', 'IP_iocs_to_keep_file'),
        ('File_iocs', 'File_iocs_to_keep_file')
    ]

    @staticmethod
    def get_file(path):
        with open(path) as _file:
            return _file.read()

    @staticmethod
    def get_all_iocs(go_over, extension):
        iocs = []
        total = 0
        data = []
        for in_iocs, out_iocs in go_over:
            ioc = json.loads(TestCreateFile.get_file(f'test_data/{in_iocs}.json'))
            iocs.extend(ioc['iocs'])
            total += ioc['total']
            data.append(TestCreateFile.get_file(f'test_data/{out_iocs}.{extension}'))

        all_iocs = {'iocs': iocs, 'total': total}
        all_data = ''.join(data)
        return all_iocs, all_data

    def test_create_file_sync_without_iocs(self, mocker):
        """
            Given:
                - Sync command
            When:
                - there is no iocs
            Then:
                - Verify sync file data.
        """
        mocker.patch.object(demisto, 'searchIndicators', return_value={"total": 0})
        with tempfile.NamedTemporaryFile(mode='w') as temp_file:
            create_file_sync(temp_file.name)
            data = self.get_file(temp_file.name)
        expected_data = ''
        assert data == expected_data, f'create_file_sync with no iocs\n\tcreates: {data}\n\tinstead: {expected_data}'

    @pytest.mark.parametrize('in_iocs, out_iocs', data_test_create_file_sync)
    def test_create_file_sync(self, in_iocs, out_iocs, mocker):
        """
            Given:
                - Sync command
            When:
                - iocs type is a specific type.
            Then:
                - Verify sync file data.
        """
        mocker.patch.object(demisto, 'searchIndicators', return_value=json.loads(self.get_file(f'test_data/{in_iocs}.json')))  # noqa: E501
        with tempfile.NamedTemporaryFile(mode='w') as temp_file:
            create_file_sync(temp_file.name)
            data = self.get_file(temp_file.name)
        expected_data = self.get_file(f'test_data/{out_iocs}.txt')
        assert data == expected_data, f'create_file_sync with {in_iocs} iocs\n\tcreates: {data}\n\tinstead: {expected_data}'

    def test_create_file_sync_all_types(self, mocker):
        """
            Given:
                - Sync command
            When:
                - iocs as all types
            Then:
                - Verify sync file data.
        """
        all_iocs, expected_data = self.get_all_iocs(self.data_test_create_file_sync, 'txt')
        mocker.patch.object(demisto, 'searchIndicators', return_value=all_iocs)
        with tempfile.NamedTemporaryFile(mode='w') as temp_file:
            create_file_sync(temp_file.name)
            data = self.get_file(temp_file.name)
        assert data == expected_data, f'create_file_sync with all iocs\n\tcreates: {data}\n\tinstead: {expected_data}'

    data_test_create_file_with_empty_indicators = [
        {},
        {'value': '11.11.11.11'},
        {'indicator_type': 'IP'}
    ]

    @pytest.mark.parametrize('defective_indicator', data_test_create_file_with_empty_indicators)
    def test_create_file_sync_with_empty_indicators(self, defective_indicator, mocker):
        """
            Given:
                - Sync command
            When:
                - a part iocs dont have all required data
            Then:
                - Verify sync file data.
        """
        all_iocs, expected_data = self.get_all_iocs(self.data_test_create_file_sync, 'txt')
        all_iocs['iocs'].append(defective_indicator)
        all_iocs['total'] += 1
        mocker.patch.object(demisto, 'searchIndicators', return_value=all_iocs)
        with tempfile.NamedTemporaryFile(mode='w') as temp_file:
            create_file_sync(temp_file.name)
            data = self.get_file(temp_file.name)
        assert data == expected_data, f'create_file_sync with all iocs\n\tcreates: {data}\n\tinstead: {expected_data}'

    def test_create_file_iocs_to_keep_without_iocs(self, mocker):
        """
            Given:
                - iocs to keep command
            When:
                - there is no iocs
            Then:
                - Verify iocs to keep file data.
        """

        mocker.patch.object(demisto, 'searchIndicators', return_value={"total": 0})
        with tempfile.NamedTemporaryFile(mode='w') as temp_file:
            create_file_iocs_to_keep(temp_file.name)
            data = self.get_file(temp_file.name)
        expected_data = ' '
        assert data == expected_data, f'create_file_iocs_to_keep with no iocs\n\tcreates: {data}\n\tinstead: {expected_data}'

    @pytest.mark.parametrize('in_iocs, out_iocs', data_test_create_file_iocs_to_keep)
    def test_create_file_iocs_to_keep(self, in_iocs, out_iocs, mocker):
        """
            Given:
                - iocs to keep command
            When:
                - iocs type is a specific type.
            Then:
                - Verify iocs to keep file data.
        """
        mocker.patch.object(demisto, 'searchIndicators', return_value=json.loads(
            self.get_file(f'test_data/{in_iocs}.json')))
        with tempfile.NamedTemporaryFile(mode='w') as temp_file:
            create_file_iocs_to_keep(temp_file.name)
            data = self.get_file(temp_file.name)
        expected_data = self.get_file(f'test_data/{out_iocs}.txt')
        assert data == expected_data, f'create_file_iocs_to_keep with {in_iocs} iocs\n\tcreates: {data}\n\tinstead: {expected_data}'    # noqa: E501

    def test_create_file_iocs_to_keep_all_types(self, mocker):
        """
            Given:
                - iocs to keep command
            When:
                - iocs as all types
            Then:
                - Verify iocs to keep file data.
        """
        all_iocs, expected_data = self.get_all_iocs(self.data_test_create_file_iocs_to_keep, 'txt')
        mocker.patch.object(demisto, 'searchIndicators', return_value=all_iocs)
        with tempfile.NamedTemporaryFile('w') as temp_file:
            create_file_iocs_to_keep(temp_file.name)
            data = self.get_file(temp_file.name)
        assert data == expected_data, f'create_file_iocs_to_keep with all iocs\n\tcreates: {data}\n\tinstead: {expected_data}'


class TestDemistoIOCToXDR:

    data_test_demisto_expiration_to_xdr = [
        (None, -1),
        ('', -1),
        ('0001-01-01T00:00:00Z', -1),
        ('2020-06-03T00:00:00Z', 1591142400000)
    ]

    @pytest.mark.parametrize('demisto_expiration, xdr_expiration', data_test_demisto_expiration_to_xdr)
    def test_demisto_expiration_to_xdr(self, demisto_expiration, xdr_expiration):
        """
            Given:
                - demisto indicator expiration
            Then:
                - Verify XDR expiration.
        """

        output = demisto_expiration_to_xdr(demisto_expiration)
        assert xdr_expiration == output, f'demisto_expiration_to_xdr({demisto_expiration})\n\treturns: {output}\n\tinstead: {xdr_expiration}'   # noqa: E501

    data_test_demisto_reliability_to_xdr = [
        (None, 'F'),
        ('A - Completely reliable', 'A'),
        ('B - Usually reliable', 'B'),
        ('C - Fairly reliable', 'C'),
        ('D - Not usually reliable', 'D'),
        ('E - Unreliable', 'E'),
        ('F - Reliability cannot be judged', 'F')
    ]

    @pytest.mark.parametrize('demisto_reliability, xdr_reliability', data_test_demisto_reliability_to_xdr)
    def test_demisto_reliability_to_xdr(self, demisto_reliability, xdr_reliability):
        """
            Given:
                - demisto indicator reliability
            Then:
                - Verify XDR reliability.
        """

        output = demisto_reliability_to_xdr(demisto_reliability)
        assert output == xdr_reliability, f'demisto_reliability_to_xdr({demisto_reliability})\n\treturns: {output}\n\tinstead: {xdr_reliability}'   # noqa: E501

    data_test_demisto_types_to_xdr = [
        ('File', 'HASH'),
        ('IP', 'IP'),
        ('Domain', 'DOMAIN_NAME'),
        ('URL', 'PATH')
    ]

    @pytest.mark.parametrize('demisto_type, xdr_type', data_test_demisto_types_to_xdr)
    def test_demisto_types_to_xdr(self, demisto_type, xdr_type):
        """
            Given:
                - demisto indicator type
            Then:
                - Verify XDR type.
        """

        output = demisto_types_to_xdr(demisto_type)
        assert output == xdr_type, f'demisto_reliability_to_xdr({demisto_type})\n\treturns: {output}\n\tinstead: {xdr_type}'

    data_test_demisto_vendors_to_xdr = [
        (
            {'moduleID': {'sourceBrand': 'test', 'reliability': 'A - Completely reliable', 'score': 2}},
            {'vendor_name': 'test', 'reputation': 'SUSPICIOUS', 'reliability': 'A'}
        ),
        (
            {'moduleID': {'reliability': 'A - Completely reliable', 'score': 2}},
            {'vendor_name': 'moduleID', 'reputation': 'SUSPICIOUS', 'reliability': 'A'}
        ),
        (
            {'moduleID': {'sourceBrand': 'test', 'score': 2}},
            {'vendor_name': 'test', 'reputation': 'SUSPICIOUS', 'reliability': 'F'}
        ),
        (
            {'moduleID': {'reliability': 'A - Completely reliable', 'score': 0}},
            {'vendor_name': 'moduleID', 'reputation': 'UNKNOWN', 'reliability': 'A'}
        )
    ]

    @pytest.mark.parametrize('demisto_vendor, xdr_vendor', data_test_demisto_vendors_to_xdr)
    def test_demisto_vendors_to_xdr(self, demisto_vendor, xdr_vendor):
        """
            Given:
                - demisto indicator vendors reports.
            Then:
                - Verify XDR vendors format.
        """

        output = demisto_vendors_to_xdr(demisto_vendor)[0]
        assert output == xdr_vendor, f'demisto_vendors_to_xdr({demisto_vendor})\n\treturns: {d_sort(output)}\n\tinstead: {d_sort(xdr_vendor)}'  # noqa: E501

    data_test_demisto_ioc_to_xdr = [
        (
            {'value': '11.11.11.11', 'indicator_type': 'IP', 'score': 2},
            {'expiration_date': -1, 'indicator': '11.11.11.11', 'reputation': 'SUSPICIOUS', 'severity': 'INFO',
             'type': 'IP', "comment": [""]}
        ),
        (
            {'value': '11.11.11.11', 'indicator_type': 100, 'score': 2},
            {'expiration_date': -1, 'indicator': '11.11.11.11', 'reputation': 'SUSPICIOUS',
             'severity': 'INFO', 'type': '100', "comment": [""]}
        ),
        (
            {'value': '11.11.11.11', 'indicator_type': 'IP'},
            {'expiration_date': -1, 'indicator': '11.11.11.11', 'reputation': 'UNKNOWN',
             'severity': 'INFO', 'type': 'IP', "comment": [""]}
        ),
        (
            {'value': '11.11.11.11', 'indicator_type': 'IP', 'expiration': '2020-06-03T00:00:00Z'},
            {'expiration_date': 1591142400000, 'indicator': '11.11.11.11', 'reputation': 'UNKNOWN', 'severity': 'INFO',
             'type': 'IP', "comment": [""]}  # noqa: E501
        ),
        (
            {'value': '11.11.11.11', 'indicator_type': 'IP',
             'comments': [{'type': 'IndicatorCommentTimeLine', 'content': 'test'}]},  # noqa: E501
            {'expiration_date': -1, 'indicator': '11.11.11.11', 'reputation': 'UNKNOWN',
             'severity': 'INFO', 'type': 'IP', "comment": [""]}
        ),
        (
            {'value': '11.11.11.11', 'indicator_type': 'IP',
             'comments': [{'type': 'IndicatorCommentRegular', 'content': 'test'}]},  # noqa: E501
            {'expiration_date': -1, 'indicator': '11.11.11.11', 'reputation': 'UNKNOWN', 'severity': 'INFO', 'type': 'IP',
             'comment': ['test']}  # noqa: E501
        ),
        (
            {'value': '11.11.11.11', 'indicator_type': 'IP', 'comments': [{'type': 'IndicatorCommentRegular', 'content': 'test'},
                                                                          {'type': 'IndicatorCommentRegular',
                                                                           'content': 'this is the comment'}]},  # noqa: E501
            {'expiration_date': -1, 'indicator': '11.11.11.11', 'reputation': 'UNKNOWN', 'severity': 'INFO', 'type': 'IP',
             'comment': ['this is the comment']}  # noqa: E501
        ),
        (
            {'value': '11.11.11.11', 'indicator_type': 'IP', 'aggregatedReliability': 'A - Completely reliable'},
            {'expiration_date': -1, 'indicator': '11.11.11.11', 'reputation': 'UNKNOWN', 'severity': 'INFO', 'type': 'IP',
             'reliability': 'A', "comment": [""]}  # noqa: E501
        ),
        (
            {'value': '11.11.11.11', 'indicator_type': 'IP', 'CustomFields': {'threattypes': {'threatcategory': 'Malware'}}},
            # noqa: E501
            {'expiration_date': -1, 'indicator': '11.11.11.11', 'reputation': 'UNKNOWN', 'severity': 'INFO', 'type': 'IP',
             'class': 'Malware', "comment": [""]}  # noqa: E501
        ),
        (
            {'value': '11.11.11.11', 'indicator_type': 'IP', 'moduleToFeedMap': {'module': {'sourceBrand': 'test', 'score': 2}}},
            # noqa: E501
            {'expiration_date': -1, 'indicator': '11.11.11.11', 'reputation': 'UNKNOWN', 'severity': 'INFO', 'type': 'IP',
             'vendors': [{'vendor_name': 'test', 'reputation': 'SUSPICIOUS', 'reliability': 'F'}], "comment": [""]}  # noqa: E501
        )
    ]

    @pytest.mark.parametrize('demisto_ioc, xdr_ioc', data_test_demisto_ioc_to_xdr)
    def test_demisto_ioc_to_xdr(self, demisto_ioc, xdr_ioc):
        """
            Given:
                - demisto indicator.
            Then:
                - Verify XDR indicator format.
        """

        output = demisto_ioc_to_xdr(demisto_ioc)
        assert output == xdr_ioc, f'demisto_ioc_to_xdr({demisto_ioc})\n\treturns: {d_sort(output)}\n\tinstead: {d_sort(xdr_ioc)}'    # noqa: E501

    def test_empty_demisto_ioc_to_xdr(self, mocker):
        warnings = mocker.patch.object(demisto, 'debug')
        output = demisto_ioc_to_xdr({})
        assert output == {}, 'demisto_ioc_to_xdr({})\n\treturns: ' + str(d_sort(output)) + '\n\tinstead: {}'
        assert warnings.call_args.args[0] == "unexpected IOC format in key: 'value', {}"


class TestXDRIOCToDemisto:

    data_test_xdr_expiration_to_demisto = [
        (-1, 'Never'),
        (1591142400000, '2020-06-03T00:00:00Z'),
        (1592142400000, '2020-06-14T13:46:40Z')
    ]

    @pytest.mark.parametrize('xdr_expiration, demisto_expiration', data_test_xdr_expiration_to_demisto)
    def test_xdr_expiration_to_demisto(self, xdr_expiration, demisto_expiration):
        """
            Given:
                - expiration in XDR format.
            Then:
                - expiration in demisto format.
        """
        output = xdr_expiration_to_demisto(xdr_expiration)
        assert output == demisto_expiration, f'xdr_expiration_to_demisto({xdr_expiration})\n\treturns: {output}\n\tinstead: {demisto_expiration}'    # noqa: E501

    data_test_xdr_ioc_to_demisto = [
        (
            {
                'RULE_ID': 863, 'RULE_INSERT_TIME': 1591165763753, 'RULE_MODIFY_TIME': 1591166095668,
                'RULE_SEVERITY': 'SEV_010_INFO', 'NUMBER_OF_HITS': 0, 'RULE_SOURCE': 'XSOAR TIM', 'RULE_COMMENT': '',
                'RULE_STATUS': 'DISABLED', 'BS_STATUS': 'DONE', 'BS_TS': 1591165801230, 'BS_RETRIES': 1,
                'RULE_EXPIRATION_TIME': -1, 'IOC_TYPE': 'HASH',
                'RULE_INDICATOR': 'fa66f1e0e318b6d7b595b6cee580dc0d8e4ac38fbc8dbfcac6ad66dbe282832e', 'REPUTATION': 'GOOD',    # noqa: E501
                'RELIABILITY': None, 'VENDORS': None, 'KLASS': None, 'IS_DEFAULT_TTL': False, 'RULE_TTL': -1,
                'MARKED_DELETED': 0
            },
            {
                'value': 'fa66f1e0e318b6d7b595b6cee580dc0d8e4ac38fbc8dbfcac6ad66dbe282832e',
                'type': 'File',
                'score': 1,
                'fields': {
                    'expirationdate': 'Never',
                    'tags': 'Cortex XDR',
                    'xdrstatus': 'disabled',
                    'sourceoriginalseverity': 'INFO',
                }
            }
        ),
        (
            {
                'RULE_ID': 861, 'RULE_INSERT_TIME': 1591165763753, 'RULE_MODIFY_TIME': 1591166095668,
                'RULE_SEVERITY': 'SEV_010_INFO', 'NUMBER_OF_HITS': 0, 'RULE_SOURCE': 'XSOAR TIM', 'RULE_COMMENT': '',
                'RULE_STATUS': 'DISABLED', 'BS_STATUS': 'DONE', 'BS_TS': 1591165801784, 'BS_RETRIES': 1,
                'RULE_EXPIRATION_TIME': -1, 'IOC_TYPE': 'DOMAIN_NAME', 'RULE_INDICATOR': 'test.com', 'REPUTATION': 'GOOD',    # noqa: E501
                'RELIABILITY': None, 'VENDORS': None, 'KLASS': None, 'IS_DEFAULT_TTL': False, 'RULE_TTL': -1,
                'MARKED_DELETED': 0
            },
            {
                'value': 'test.com',
                'type': 'Domain',
                'score': 1,
                'fields': {
                    'expirationdate': 'Never',
                    'tags': 'Cortex XDR',
                    'xdrstatus': 'disabled',
                    'sourceoriginalseverity': 'INFO',
                }
            }
        ),
        (
            {
                'RULE_ID': 862, 'RULE_INSERT_TIME': 1591165763753, 'RULE_MODIFY_TIME': 1591166095668,
                'RULE_SEVERITY': 'SEV_010_INFO', 'NUMBER_OF_HITS': 0, 'RULE_SOURCE': 'XSOAR TIM', 'RULE_COMMENT': '',
                'RULE_STATUS': 'ENABLED', 'BS_STATUS': 'DONE', 'BS_TS': 1591165801784, 'BS_RETRIES': 1,
                'RULE_EXPIRATION_TIME': -1, 'IOC_TYPE': 'DOMAIN_NAME', 'RULE_INDICATOR': 'test.co.il',
                'REPUTATION': 'SUSPICIOUS', 'RELIABILITY': 'A',
                'VENDORS': [{'vendor_name': 'Cortex XDR - IOC', 'reputation': 'SUSPICIOUS', 'reliability': 'A'}],
                'KLASS': None,
                'IS_DEFAULT_TTL': False, 'RULE_TTL': -1, 'MARKED_DELETED': 0
            },
            {
                'value': 'test.co.il',
                'type': 'Domain',
                'score': 2,
                'fields': {
                    'expirationdate': 'Never',
                    'tags': 'Cortex XDR',
                    'xdrstatus': 'enabled',
                    'sourceoriginalseverity': 'INFO',
                }
            }
        )
    ]

    @pytest.mark.parametrize('xdr_ioc, demisto_ioc', data_test_xdr_ioc_to_demisto)
    def test_xdr_ioc_to_demisto(self, xdr_ioc, demisto_ioc, mocker):
        """
            Given:
                - IOC in XDR format.
            Then:
                - IOC in demisto format.
        """
        mocker.patch.object(demisto, 'searchIndicators', return_value={"total": 0})
        output = xdr_ioc_to_demisto(xdr_ioc)
        del output['rawJSON']
        assert output == demisto_ioc, f'xdr_ioc_to_demisto({xdr_ioc})\n\treturns: {d_sort(output)}\n\tinstead: {d_sort(demisto_ioc)}'    # noqa: E501


class TestCommands:
    # test commands full flow
    class TestIOCSCommand:
        def test_iocs_command_with_enable(self, mocker):
            """
                Given:
                    - enable command
                Then:
                    - Verify enable command is called.
            """
            mocker.patch.object(demisto, 'command', return_value='xdr-iocs-enable')
            mocker.patch.object(demisto, 'args', return_value={'indicator': '11.11.11.11'})
            mocker.patch('XDR_iocs.Client.http_request', return_value={})
            outputs = mocker.patch('XDR_iocs.return_outputs')
            enable_ioc = mocker.patch('XDR_iocs.prepare_enable_iocs', side_effect=prepare_enable_iocs)
            iocs_command(client)
            output = outputs.call_args.args[0]
            assert output == "IOCs command: enabled indicators='11.11.11.11'", f"enable command\n\tprints:  {output}\n\tinstead: IOCs command: enabled indicators='11.11.11.11'."    # noqa: E501
            assert enable_ioc.call_count == 1, 'enable command not called'

        def test_iocs_command_with_disable(self, mocker):
            """
                Given:
                    - disable command
                Then:
                    - Verify disable command is called.
            """

            mocker.patch.object(demisto, 'command', return_value='xdr-iocs-disable')
            mocker.patch.object(demisto, 'args', return_value={'indicator': '11.11.11.11'})
            mocker.patch('XDR_iocs.Client.http_request', return_value={})
            outputs = mocker.patch('XDR_iocs.return_outputs')
            disable_ioc = mocker.patch('XDR_iocs.prepare_disable_iocs', side_effect=prepare_disable_iocs)
            iocs_command(client)
            output = outputs.call_args.args[0]
            assert output == "IOCs command: disabled indicators='11.11.11.11'", f"enable command\n\tprints:  {output}\n\tinstead: IOCs command: disabled indicators='11.11.11.11'."    # noqa: E501
            assert disable_ioc.call_count == 1, 'disable command not called'

    def test_sync(self, mocker):
        http_request = mocker.patch.object(Client, 'http_request')
        iocs, _ = TestCreateFile.get_all_iocs(TestCreateFile.data_test_create_file_sync, 'txt')
        mocker.patch.object(demisto, 'searchIndicators', returnvalue=iocs)
        mocker.patch('XDR_iocs.return_outputs')
        sync(client)
        assert http_request.call_args.args[0] == 'sync_tim_iocs', 'sync command url changed'

    @pytest.mark.parametrize("zip_value, expected_file_name", [pytest.param(False, 'xdr-sync-file', id="no zip"),
                                                               pytest.param(True, "xdr-sync-file-zipped.zip", id="zip")])
    def test_get_sync_file(self, mocker, zip_value: bool, expected_file_name: str):
        iocs, _ = TestCreateFile.get_all_iocs(TestCreateFile.data_test_create_file_sync, 'txt')
        mocker.patch.object(demisto, 'searchIndicators', returnvalue=iocs)
        return_results_mock = mocker.patch('XDR_iocs.return_results')
        get_sync_file(zip=zip_value)
        assert return_results_mock.call_args[0][0]['File'] == expected_file_name

    def test_tim_insert_jsons(self, mocker):
        http_request = mocker.patch.object(Client, 'http_request')
        http_request.return_value = {'reply': {'success': True}}
        mocker.patch.object(demisto, 'getIntegrationContext', return_value={'time': '2020-06-03T00:00:00Z'})
        iocs, _ = TestCreateFile.get_all_iocs(TestCreateFile.data_test_create_file_sync, 'txt')
        mocker.patch.object(demisto, 'searchIndicators', side_effect=[iocs, {"total": 0}])
        mocker.patch('XDR_iocs.return_outputs')
        tim_insert_jsons(client)
        assert http_request.call_args.kwargs['url_suffix'] == 'tim_insert_jsons/', 'tim_insert_jsons command url changed'

    def test_get_changes(self, mocker):
        mocker.patch.object(demisto, 'getIntegrationContext', return_value={'ts': 1591142400000})
        mocker.patch.object(demisto, 'createIndicators')
        mocker.patch.object(demisto, 'searchIndicators', return_value={"total": 0})
        xdr_res = {'reply': [xdr_ioc[0] for xdr_ioc in TestXDRIOCToDemisto.data_test_xdr_ioc_to_demisto]}
        mocker.patch.object(Client, 'http_request', return_value=xdr_res)
        get_changes(client)
        xdr_ioc_to_timeline([str(x[0].get('RULE_INDICATOR')) for x in TestXDRIOCToDemisto.data_test_xdr_ioc_to_demisto])    # noqa: E501


class TestParams:
    tags_test = [
        (
            {'value': '11.11.11.11', 'indicator_type': 'IP', 'score': 2},
            {'expiration_date': -1, 'indicator': '11.11.11.11', 'reputation': 'SUSPICIOUS', 'severity': 'INFO',
             'type': 'IP'},
            {'tlp_color': ''},
            'Cortex XDR',
            None
        ),
        (
            {'value': '11.11.11.11', 'indicator_type': 'IP', 'score': 2},
            {'expiration_date': -1, 'indicator': '11.11.11.11', 'reputation': 'SUSPICIOUS', 'severity': 'INFO',
             'type': 'IP'},
            {'tag': 'tag1'},
            'tag1',
            None
        ),
        (
            {'value': '11.11.11.11', 'indicator_type': 'IP', 'score': 2},
            {'expiration_date': -1, 'indicator': '11.11.11.11', 'reputation': 'SUSPICIOUS', 'severity': 'INFO',
             'type': 'IP'},
            {'feedTags': 'tag2', 'tlp_color': 'AMBER'},
            'tag2',
            'AMBER'
        )
    ]

    @pytest.mark.parametrize('demisto_ioc, xdr_ioc, param_value, expected_tags, expected_tlp_color', tags_test)
    def test_feed_tags_and_tlp_color(self, demisto_ioc, xdr_ioc, param_value, expected_tags, expected_tlp_color, mocker):
        """
            Given:
                - IOC in XDR format.

            Then:
                - IOC in demisto format.
        """
        mocker.patch.object(demisto, 'searchIndicators', return_value={"total": 0})
        mocker.patch.object(demisto, 'params', return_value=param_value)
        mocker.patch.object(demisto, 'getIntegrationContext', return_value={'ts': 1591142400000})
        mocker.patch.object(demisto, 'searchIndicators', return_value={"total": 0})
        outputs = mocker.patch.object(demisto, 'createIndicators')
        Client.tag = demisto.params().get('feedTags', demisto.params().get('tag', Client.tag))
        Client.tlp_color = demisto.params().get('tlp_color')
        client = Client({'url': 'yana'})
        xdr_res = {'reply': [xdr_ioc[0] for xdr_ioc in TestXDRIOCToDemisto.data_test_xdr_ioc_to_demisto]}
        mocker.patch.object(Client, 'http_request', return_value=xdr_res)
        get_changes(client)
        output = outputs.call_args.args[0]
        assert output[0]['fields']['tags'] == expected_tags
        assert output[0]['fields'].get('trafficlightprotocol') == expected_tlp_color


def test_file_deleted_for_create_file_sync(mocker):
    file_path = 'test'
    mocker.patch('XDR_iocs.get_temp_file', return_value=file_path)
    open(file_path, 'w').close()

    def raise_function(*_args, **_kwargs):
        raise DemistoException(file_path)

    mocker.patch('XDR_iocs.create_file_sync', new=raise_function)
    with pytest.raises(DemistoException):
        get_sync_file(set_time=False, zip=False)
    assert os.path.exists(file_path) is False


data_test_test_file_deleted = [
    (sync, 'create_file_sync')
]


@pytest.mark.parametrize('method_to_test,iner_method', data_test_test_file_deleted)
@freeze_time('2020-06-03T02:00:00Z')
def test_file_deleted(mocker, method_to_test, iner_method):
    file_path = 'test'
    mocker.patch('XDR_iocs.get_temp_file', return_value=file_path)
    open(file_path, 'w').close()

    def raise_function(*_args, **_kwargs):
        raise DemistoException(file_path)

    mocker.patch(f'XDR_iocs.{iner_method}', new=raise_function)
    with pytest.raises(DemistoException):
        method_to_test(None)
    assert os.path.exists(file_path) is False


data_test_batch = [
    ([], 200, []),
    ([], 1, []),
    (range(3), 200, [[0, 1, 2]]),
    (range(3), 2, [[0, 1], [2]]),
    (range(4), 2, [[0, 1], [2, 3]]),
    (range(4), 1, [[0], [1], [2], [3]]),
]


@pytest.mark.parametrize('input_enumerator, batch_size, expected_output', data_test_batch)
def test_batch_iocs(input_enumerator, batch_size, expected_output):
    assert list(batch_iocs(input_enumerator, batch_size=batch_size)) == expected_output


def test_overriding_severity_xsoar():
    # back up class attributes
    xsoar_severity_field_backup = Client.xsoar_severity_field
    severity_value_backup = Client.severity

    # for testing
    Client.severity = 'LOW'

    # constants
    custom_severity_field = 'custom_severity_field'
    dummy_demisto_ioc = {'value': '1.1.1.1', 'indicator_type': 'FILE_123',
                         'CustomFields': {custom_severity_field: 'critical'}}

    # default behavior
    assert Client.override_severity is True
    assert demisto_ioc_to_xdr(dummy_demisto_ioc)['severity'] == 'LOW'

    # behavior when override_severity is False
    Client.override_severity = False
    Client.xsoar_severity_field = custom_severity_field
    assert demisto_ioc_to_xdr(dummy_demisto_ioc)['severity'] == 'CRITICAL'

    # behavior when there is no custom severity value
    dummy_demisto_ioc['CustomFields'][custom_severity_field] = None
    assert demisto_ioc_to_xdr(dummy_demisto_ioc)['severity'] == Client.severity

    # behavior when there is no custom severity field
    del dummy_demisto_ioc['CustomFields'][custom_severity_field]
    assert demisto_ioc_to_xdr(dummy_demisto_ioc)['severity'] == Client.severity

    # restore class attributes
    Client.override_severity = True
    Client.severity = severity_value_backup
    Client.xsoar_severity_field = xsoar_severity_field_backup


def test_overriding_severity_xdr_to_demisto():
    # back up class attributes
    xsoar_severity_field_backup = Client.xsoar_severity_field
    severity_value_backup = Client.severity

    Client.severity = 'some hardcoded severity value'
    severity_field = 'custom_severity_field'

    Client.xsoar_severity_field = severity_field
    dummy_xdr_ioc = {'IOC_TYPE': 'IP', 'RULE_EXPIRATION_TIME': -1, 'RULE_SEVERITY': 'SEV_050_CRITICAL'}

    # default behavior
    assert Client.override_severity is True  # this should always be the default
    assert xdr_ioc_to_demisto(dummy_xdr_ioc)['fields'][severity_field] == Client.severity

    # behavior when override_severity is False
    Client.override_severity = False
    assert xdr_ioc_to_demisto(dummy_xdr_ioc)['fields'][severity_field] == 'CRITICAL'

    # restore class attributes
    Client.override_severity = True
    Client.severity = severity_value_backup
    Client.xsoar_severity_field = xsoar_severity_field_backup


@pytest.mark.parametrize('value', (
    'info',
    'Info',
    'informational',
    'INformationAL'
))
def test_severity_fix_info(value: str):
    """
    given
            a severity value that should be fixed to INFO
    when
            calling validate_fix_severity_value
    then
            make sure the value returned INFO
    """
    assert validate_fix_severity_value(value) == 'INFO'


@pytest.mark.parametrize('value', ('', 'a', 'foo', 'severity', 'infoo', 'informationall'))
def test_severity_validate(value: str):
    with pytest.raises(DemistoException):
        validate_fix_severity_value(value)


def test_parse_demisto_comments__default():
    """
    Given   a custom field name, and comma-separated comments in it
    When    parsing a comment of the default comment field
    Then    check the output values
    """
    from XDR_iocs import _parse_demisto_comments
    comment_value = 'here be comment'
    assert _parse_demisto_comments(
        ioc={Client.xsoar_comments_field: [{'type': 'IndicatorCommentRegular', 'content': comment_value}]},
        comment_field_name=Client.xsoar_comments_field,
        comments_as_tags=False
    ) == [comment_value]


def test_parse_demisto_comments__default_empty():
    """
    Given   a custom field name, and comma-separated comments in it
    When    parsing a comment of the default comment field
    Then    check parsing a comment results in None.
    """
    from XDR_iocs import _parse_demisto_comments
    assert _parse_demisto_comments(
        ioc={},
        comment_field_name=Client.xsoar_comments_field,
        comments_as_tags=False
    ) == ['']


def test_parse_demisto_comments__default_as_tag():
    """
    Given   a custom field name
    When    parsing a comment of the default comment field, passing comments_as_tags=True
    Then    make sure an appropriate exception is raised
    """
    from XDR_iocs import _parse_demisto_comments
    with pytest.raises(DemistoException) as exc:
        _parse_demisto_comments(
            ioc={Client.xsoar_comments_field: [{'type': 'IndicatorCommentRegular', 'content': 'whatever'}]},
            comment_field_name=Client.xsoar_comments_field,
            comments_as_tags=True
        )
    assert exc.value.message == "When specifying comments_as_tags=True, the xsoar_comment_field cannot be `comments`)."\
                                "Set a different value."


@pytest.mark.parametrize('comment_value,comments_as_tags,expected', (
    ('hello', True, ['hello']),
    ('hello', False, ['hello']),
    ('hello,world', True, ['hello', 'world']),
    ('hello,world', False, ['hello,world']),
))
def test_parse_demisto_comments__custom_field(comment_value: str, comments_as_tags: bool, expected: str):
    """
    Given   a custom field name
    When    parsing a comment of a non-default comment field
    Then    make sure the comment is parsed as expected
    """
    from XDR_iocs import _parse_demisto_comments
    comment_field = 'comment_field'
    Client.xsoar_comments_field = 'comment_field'
    assert _parse_demisto_comments(
        ioc={'CustomFields': {comment_field: comment_value}},
        comment_field_name=comment_field,
        comments_as_tags=comments_as_tags
    ) == expected


@pytest.mark.parametrize('comments_as_tags', (True, False))
def test_parse_demisto_comments__custom_field_empty_value(comments_as_tags: bool):
    """
    Given   a custom field name, and an empty value as
    When    parsing a comment of a non-default comment field
    Then    make sure the comment is parsed as expected
    """
    from XDR_iocs import _parse_demisto_comments
    comment_field = 'comment_field'

    assert _parse_demisto_comments(
        ioc={'CustomFields': {comment_field: ''}},
        comment_field_name=comment_field,
        comments_as_tags=comments_as_tags
    ) == ['']


@pytest.mark.parametrize('comments_as_tags', (True, False))
def test_parse_demisto_comments__custom_field_missing(comments_as_tags: bool):
    """
    Given   a custom field name, which does not exist in the IOC
    When    parsing a comment
    Then    make sure the comment is parsed as expected
    """
    from XDR_iocs import _parse_demisto_comments

    assert _parse_demisto_comments(
        ioc={'CustomFields': {}},
        comment_field_name='comment_field',
        comments_as_tags=comments_as_tags
    ) == ['']


@pytest.mark.parametrize(
    'raw_comment,comments_as_tags,expected_comment', (
        ('hello', True, ['hello']),
        ('hello', False, ['hello']),
        ('hello,world', True, ['hello', 'world']),
        ('hello,world', False, ['hello,world']),
        ('', True, []),
        ('', False, []),
    ))
def test_parse_xdr_comments(raw_comment: str | list[str], comments_as_tags: bool, expected_comment: str | None):
    """
    Given   a custom field name, and comma-separated comments in it
    When    converting an XSOAR IOC to XDR
    Then    check the output values
    """
    from XDR_iocs import _parse_xdr_comments
    assert _parse_xdr_comments(raw_comment, comments_as_tags) == expected_comment


@pytest.mark.parametrize(
    'validation_errors, expected_str', (
        ([{'indicator': '1.1.1.1',
           'error': 'Expiration time 1696323079000 is invalid; expiration date cannot be in the past'},
          {'indicator': '3.3.3.3',
           'error': 'Expiration time 1696150302000 is invalid; expiration date cannot be in the past'}],
         'Expiration time 1696323079000 is invalid; expiration date cannot be in the past'),
        ([{'indicator': '1.1.1.1',
           'error': 'Expiration time 1696323079000 is invalid; expiration date cannot be in the past'}],
         'Expiration time 1696323079000 is invalid; expiration date cannot be in the past'),
        ([],
         ''),
    ))
def test_create_validation_errors_response(validation_errors, expected_str):
    """
    Given   validation errors that returned from the server.
    When    pushing XSOAR IOC to XDR
    Then    check the parsed error
    """
    from XDR_iocs import create_validation_errors_response
    assert expected_str in create_validation_errors_response(validation_errors)


def test_parse_demisto_comments_url_xsoar_6_default(mocker):
    """
    Given:
        -  xsoar version 6, a custom field name, and comma-separated comments in it
    When:
        -  parsing a comment of the url indicator field
    Then:
        - check the output values
    """
    from XDR_iocs import _parse_demisto_comments
    inc_id = '111111'
    mocker.patch.object(demisto, 'demistoUrls', return_value={'server': 'url'})
    Client.add_link_as_a_comment = True
    assert _parse_demisto_comments(
        ioc={'id': inc_id},
        comment_field_name='',
        comments_as_tags=False
    ) == [f'url/#/indicator/{inc_id}']


def test_parse_demisto_comments_url_xsoar_8_default(mocker):
    """
    Given:
        -  xsoar version that is greater than 8, a custom field name, and comma-separated comments in it
    When:
        -  parsing a comment of the url indicator field
    Then:
        - check the output values
    """
    import XDR_iocs
    os.environ['CRTX_HTTP_PROXY'] = 'xsoar_8_proxy'
    inc_id = '111111'
    mocker.patch.object(demisto, 'demistoUrls', return_value={'server': 'url'})
    mocker.patch.object(XDR_iocs, 'is_xsoar_saas', return_value=True)
    Client.add_link_as_a_comment = True
    assert XDR_iocs._parse_demisto_comments(
        ioc={'id': inc_id},
        comment_field_name='',
        comments_as_tags=False
    ) == [f'url/indicator/{inc_id}']


def test_parse_demisto_list_of_comments_default(mocker):
    """
    Given   a custom field name, and comma-separated comments in it
    When    parsing a comment of the url indicator field
    Then    check the output values
    """
    from XDR_iocs import _parse_demisto_comments
    inc_id = '111111'
    comment_value = 'here be comment'
    mocker.patch.object(demisto, 'demistoUrls', return_value={'server': 'url'})
    Client.xsoar_comments_field, Client.add_link_as_a_comment = "comments", True
    assert _parse_demisto_comments(
        ioc={Client.xsoar_comments_field: [{'type': 'IndicatorCommentRegular', 'content': comment_value}],
             'id': inc_id},
        comment_field_name=Client.xsoar_comments_field,
        comments_as_tags=False) == [f'{comment_value}, url/#/indicator/{inc_id}']


@patch('XDR_iocs.demisto.params', return_value={'feed': True, 'feedFetchInterval': '14'})
def test_module_fail_with_fetch_interval(mocker):
    """
    Given   The demisto.params() returns parameters with feed set to True and feedFetchInterval set to '15'.
    When    The module_test() function is called.
    Then    Raise a DemistoException with the message: "'Feed Fetch Interval' parameter should be 15 or larger."
    """
    from XDR_iocs import module_test
    with pytest.raises(DemistoException) as e:
        module_test(client)
    assert e.value.message == ("`Feed Fetch Interval` is set to 14. Setting `Feed Fetch Interval` to less "
                               "then 15 minutes could lead to internal error from xdr side.")


ioc_example = {
    'value': 'malicious.com',
    'modified': '2023-09-09T12:00:00Z',
    'indicator_type': 'Domain',
    'score': 3,
    'expiration': '2024-09-09T12:00:00Z',
    'aggregatedReliability': ['A'],
    'moduleToFeedMap': {
        'FeedA': {'reliability': 'A'}
    },
    'CustomFields': {
        'threattypes': [{'threatcategory': 'Malware'}],
        'xdrstatus': 'enabled',
        'sourceoriginalseverity': 'high',
    }
}


@patch('XDR_iocs.get_integration_context', return_value={'time': '2024-09-10T12:13:57Z'})
@patch('XDR_iocs.get_iocs_generator', return_value=[ioc_example])
@patch('XDR_iocs.Client.http_request', return_value={'reply': {'success': True}})
@patch('XDR_iocs.set_integration_context', return_value={})
@patch('XDR_iocs.update_integration_context_override', return_value={})
def test_xdr_iocs_sync_command_sync_for_fetch(mock_update_integration_context_override,
                                              mock_set_integration_context,
                                              mock_http_request,
                                              mock_get_iocs_generator,
                                              mock_get_integration_context):
    """
    Given   xdr_iocs_sync_command function is called with is_first_stage_sync=true, called_from_fetch=true
    When   the http_request is successful,
    Then   the update_integration_context function should be called with update_is_first_sync_phase='false'
    """
    xdr_iocs_sync_command(client, is_first_stage_sync=True, called_from_fetch=True)
    mock_update_integration_context_override.assert_called_with(update_is_first_sync_phase='false')


@patch('XDR_iocs.get_integration_context', return_value={'time': '2024-09-10T12:13:57Z'})
@patch('XDR_iocs.get_iocs_generator', return_value=[ioc_example])
@patch('XDR_iocs.Client.http_request', return_value={'reply': {'success': False}})
@patch('XDR_iocs.set_integration_context', return_value={})
@patch('XDR_iocs.update_integration_context', return_value={})
def test_xdr_iocs_sync_command_sync_for_fetch_fails(mock_update_integration_context,
                                                    mock_set_integration_context,
                                                    mock_http_request,
                                                    mock_get_iocs_generator,
                                                    mock_get_integration_context):
    """
    Given   that the xdr_iocs_sync_command function is called with is_first_stage_sync=true, called_from_fetch=true
    When    the http_request fails
    Then    Raises DemistoException
    """
    with pytest.raises(DemistoException) as e:
        xdr_iocs_sync_command(client, is_first_stage_sync=True, called_from_fetch=True)
    assert e.value.message == ("Failed to sync indicators with error Response status was not success, "
                               "response={'reply': {'success': False}}.")


@patch('XDR_iocs.get_integration_context', return_value={'time': '2024-09-10T12:13:57Z'})
@patch('XDR_iocs.get_iocs_generator', return_value=[ioc_example])
@patch('XDR_iocs.Client.http_request', return_value={'reply': {'success': True, 'validation_errors': [
    {'indicator': '123', 'error': 'error1'},
    {'indicator': '456', 'error': 'error2'}]}})
@patch('XDR_iocs.set_integration_context', return_value={})
@patch('XDR_iocs.update_integration_context_override', return_value={})
@patch('XDR_iocs.demisto.debug')
def test_xdr_iocs_sync_command_sync_for_fetch_with_validation_errors(
        mock_demisto_debug,
        mock_update_integration_context_override,
        mock_set_integration_context,
        mock_http_request,
        mock_get_iocs_generator,
        mock_get_integration_context):
    """
    Given the xdr_iocs_sync_command function is called with is_first_stage_sync=true, called_from_fetch=true
    When  There are validation errors in the response
    Then update_integration_context should be called with update_is_first_sync_phase='false',
        and a debug message should be logged indicating the validation errors.
    """
    xdr_iocs_sync_command(client, is_first_stage_sync=True, called_from_fetch=True)
    mock_update_integration_context_override.assert_called_with(update_is_first_sync_phase='false')
    debug_calls = [call.args[0] for call in mock_demisto_debug.call_args_list]
    expected_debug_message = ('pushing IOCs to XDR:The following 2 IOCs were not pushed due to following errors:123: error1.456:'
                              ' error2.')
    assert any(expected_debug_message in call for call in debug_calls), \
        f"Expected debug message not found in: {debug_calls}"


@patch('XDR_iocs.get_integration_context', return_value={'time': '2024-09-10T12:13:57Z',
                                                         'ts': '1234567',
                                                         'is_first_sync_phase': True,
                                                         'search_after': ['1234', '098765']})
@patch('XDR_iocs.set_integration_context')
def test_update_integration_context(mock_set_integration_context, mock_get_integration_context):
    """
    Given integration_context has some values
    When  update_integration_context (of XDR_iocs) is being called with all args
    Then  The integration context is being changed
    """
    fixed_datetime = datetime(2024, 9, 10, 12, 0, 0, tzinfo=timezone.utc)
    update_integration_context_override(update_sync_time_with_datetime=fixed_datetime,
                                        update_is_first_sync_phase='false',
                                        update_search_after_array=['765', '000'])
    mock_set_integration_context.assert_called_with({'time': '2024-09-10T12:00:00Z',
                                                     'ts': 1725969600000,
                                                     'is_first_sync_phase': False,
                                                     'search_after': ['765', '000']})


@patch('XDR_iocs.get_integration_context')
@patch('XDR_iocs.sync')
def test_xdr_iocs_sync_command(mock_sync, mock_integration_context):
    """
    Given:
    - first_time is true - as this is the first sync phase
    - integration context is empty
    When:
    - xdr_iocs_sync_command is called not from a fetch_indicators command
    Then:
    - The sync command is being called
    """
    client = MagicMock()
    # Test case 1: first_time is true
    xdr_iocs_sync_command(client, first_time=True)
    mock_sync.assert_called_with(client, batch_size=4000)
    mock_sync.reset_mock()
    # Test case 2: integration context is empty
    mock_integration_context.return_value = {}
    xdr_iocs_sync_command(client)
    mock_sync.assert_called_with(client, batch_size=4000)


@patch('XDR_iocs.get_integration_context')
@patch('XDR_iocs.sync_for_fetch')
def test_xdr_iocs_sync_command_from_fetch(mock_sync_for_fetch, mock_integration_context):
    """
    Given:
    - first_time is true- as this is the first sync phase
    - integration context is empty
    When:
    - xdr_iocs_sync_command is called from a fetch_indicators command
    Then:
    - The sync_for_fetch command is being called
    """
    client = MagicMock()
    xdr_iocs_sync_command(client, called_from_fetch=True, is_first_stage_sync=True)
    mock_sync_for_fetch.assert_called_with(client, batch_size=4000)
    mock_sync_for_fetch.reset_mock()
    mock_integration_context.return_value = {}
    xdr_iocs_sync_command(client, called_from_fetch=True)
    mock_sync_for_fetch.assert_called_with(client, batch_size=4000)


@pytest.mark.parametrize("indicators_input, search_results, expected_iocs, expected_warning, expected_info", [
    ('indicator1,indicator2',
     [{'iocs': ['ioc1']}, {'iocs': ['ioc2']}],
     ['ioc1', 'ioc2'],
     None,
     'get_indicators found 2 IOCs'),
    ('indicator1,indicator2',
     [{'iocs': ['ioc1']}, {'iocs': []}],
     ['ioc1'],
     '1 indicators were not found: indicator2',
     'get_indicators found 1 IOCs'),
    ('indicator1,indicator2',
     [{'iocs': None}, {'iocs': None}],
     [],
     '2 indicators were not found: indicator1,indicator2',
     '2 indicators were not found: indicator1,indicator2'),
    ('',
     [],
     [],
     None,
     None)
])
@patch('XDR_iocs.demisto.debug')
@patch('XDR_iocs.demisto.info')
@patch('XDR_iocs.return_warning')
@patch('XDR_iocs.IndicatorsSearcher')
def test_get_indicators(mock_IndicatorsSearcher,
                        mock_return_warning,
                        mock_info,
                        mock_debug,
                        indicators_input,
                        search_results,
                        expected_iocs,
                        expected_warning,
                        expected_info):
    mock_searcher_instance = MagicMock()
    mock_searcher_instance.search_indicators_by_version.side_effect = search_results
    mock_IndicatorsSearcher.return_value = mock_searcher_instance
    result = get_indicators(indicators_input)
    assert result == expected_iocs
    if expected_warning:
        mock_return_warning.assert_called_with(expected_warning)
    else:
        mock_return_warning.assert_not_called()
    if expected_info:
        mock_info.assert_called_with(expected_info)
    else:
        mock_info.assert_not_called()


@pytest.mark.parametrize('is_xsoar_saas, expected_link', ((True, ['url/indicator/111']), (False, ['url/#/indicator/111'])))
def test_create_an_indicator_link(mocker, is_xsoar_saas: bool, expected_link: str):
    """
    Given:
        -  indicator id and a bool argument is_xsoar_saas which presents if xsaor is a saas version or not
    When:
        -  creating an indicator link
    Then:
        - verify the link according to the XSAOR version
    """
    import XDR_iocs
    mocker.patch.object(demisto, 'demistoUrls', return_value={'server': 'url'})
    mocker.patch.object(XDR_iocs, 'is_xsoar_saas', return_value=is_xsoar_saas)
    assert XDR_iocs.create_an_indicator_link(ioc={'id': '111'}) == expected_link


@pytest.mark.parametrize('xsoar_comment_field, expected_result',
                         ((["indicator_link"], ("comments", True)),
                          (["comments"], ("comments", False)),
                          (["comments", "indicator_link"], ("comments", True)),
                          ))
def test_parse_xsoar_field_name_and_link(xsoar_comment_field: list[str], expected_result: tuple[str, bool]):
    """
    Given:
        -  xsoar_comment_field
    When:
        -  parsing xsoar_comment_field by our logic
    Then:
        - verify the function parses the xsoar_comment_field as expected
    """
    import XDR_iocs
    result = XDR_iocs.parse_xsoar_field_name_and_link(xsoar_comment_field)
    assert result == expected_result


@pytest.mark.parametrize('xsoar_comment_field, informative_message',
                         ((["comments", "not_indicator_link"],
                           "The parameter xsoar_comment_field=['comments', 'not_indicator_link'] "
                           "should only contain the field name,"
                           " or the field name with the phrase indicator_link, separated by a comma."),
                          (["a", "b", "c"], ("The parameter xsoar_comment_field=['a', 'b', 'c'] cannot contain more than "
                                             'two values'))))
def test_parse_xsoar_field_name_and_link_exceptions(xsoar_comment_field: list[str], informative_message: str):
    """
    Given:
        -  invalid xsoar_comment_field and the expected_result
    When:
        -  parsing xsoar_comment_field by our logic
    Then:
        - verify the function throws a DemistoException with informative message
    """
    import XDR_iocs
    with pytest.raises(DemistoException) as de:
        XDR_iocs.parse_xsoar_field_name_and_link(xsoar_comment_field)
        assert de.message == informative_message
