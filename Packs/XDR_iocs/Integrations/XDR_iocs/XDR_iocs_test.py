from XDR_iocs import *
import pytest
from freezegun import freeze_time


Client.severity = 'INFO'
client = Client({'url': 'test'})


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
            "apikey": "t3PkfrEhaRAD9a3r6Lq5cVPyqdMqtLd8cOJlSWUtbslkbERUgb2BTkSNRtDr3C6CWAgYqxvyzwDFJ83BLBgu1V2cxQY7rsoo2ks2u3W2aBL2BlteF8C8u75lCVUrNbv1"    # noqa: E501
        }
        headers = {
            'Authorization': 'da94963b561e3c95899d843b1284cecf410606e9e809be528ec1cf03880c6e9e',
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
    class Res:
        content = 'error'.encode()

        def __init__(self, code):
            self.status_code = code

        @staticmethod
        def json():
            return {}

    XDR_SERVER_ERROR = 500
    INVALID_CREDS = 401
    LICENSE_ERROR = 402
    PERMISSION_ERROR = 403
    OK = 200
    data_test_http_request_error_codes = [
        (OK, {}),
        (XDR_SERVER_ERROR, 'XDR internal server error.\t(error)'),
        (INVALID_CREDS, 'Unauthorized access. An issue occurred during authentication. This can indicate an incorrect key, id, or other invalid authentication parameters.\t(error)'),  # noqa: E501
        (LICENSE_ERROR, 'Unauthorized access. User does not have the required license type to run this API.\t(error)'),
        (PERMISSION_ERROR, 'Unauthorized access. The provided API key does not have the required RBAC permissions to run this API.\t(error)')   # noqa: E501
    ]

    @pytest.mark.parametrize('res, expected_output', data_test_http_request_error_codes)
    def test_http_request_error_codes(self, res, expected_output, mocker):
        """
            Given:
                - Status code

            When:
                - http_request returns this status code.

            Then:
                - Verify error/success format.
        """
        mocker.patch('requests.post', return_value=self.Res(res))
        try:
            output = client.http_request('', {})
        except DemistoException as error:
            output = str(error)
        assert output == expected_output, f'status code {res}\n\treturns: {output}\n\tinstead: {expected_output}'


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

    def setup(self):
        # creates the file
        with open(TestCreateFile.path, 'w') as _file:
            _file.write('')

    def teardown(self):
        # removes the file when done
        os.remove(TestCreateFile.path)

    @staticmethod
    def get_file(path):
        with open(path, 'r') as _file:
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
        mocker.patch.object(demisto, 'searchIndicators', return_value={})
        create_file_sync(TestCreateFile.path)
        data = self.get_file(TestCreateFile.path)
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
        create_file_sync(TestCreateFile.path)
        data = self.get_file(TestCreateFile.path)
        expected_data = self.get_file(f'test_data/{out_iocs}.json')
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
        all_iocs, expected_data = self.get_all_iocs(self.data_test_create_file_sync, 'json')
        mocker.patch.object(demisto, 'searchIndicators', return_value=all_iocs)
        create_file_sync(TestCreateFile.path)
        data = self.get_file(TestCreateFile.path)
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
        all_iocs, expected_data = self.get_all_iocs(self.data_test_create_file_sync, 'json')
        all_iocs['iocs'].append(defective_indicator)
        all_iocs['total'] += 1
        mocker.patch.object(demisto, 'searchIndicators', return_value=all_iocs)
        warnings = mocker.patch.object(demisto, 'debug')
        create_file_sync(TestCreateFile.path)
        data = self.get_file(TestCreateFile.path)
        assert data == expected_data, f'create_file_sync with all iocs\n\tcreates: {data}\n\tinstead: {expected_data}'
        error_msg = warnings.call_args.args[0]
        assert error_msg.startswith("unexpected IOC format in key: '"), f"create_file_sync empty message\n\tstarts: {error_msg}\n\tinstead: unexpected IOC format in key: '"    # noqa: E501
        assert error_msg.endswith(f"', {str(defective_indicator)}"), f"create_file_sync empty message\n\tends: {error_msg}\n\tinstead: ', {str(defective_indicator)}"     # noqa: E501

    def test_create_file_iocs_to_keep_without_iocs(self, mocker):
        """
            Given:
                - iocs to keep command

            When:
                - there is no iocs

            Then:
                - Verify iocs to keep file data.
        """

        mocker.patch.object(demisto, 'searchIndicators', return_value={})
        create_file_iocs_to_keep(TestCreateFile.path)
        data = self.get_file(TestCreateFile.path)
        expected_data = ''
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
        create_file_iocs_to_keep(TestCreateFile.path)
        data = self.get_file(TestCreateFile.path)
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
        create_file_iocs_to_keep(TestCreateFile.path)
        data = self.get_file(TestCreateFile.path)
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
        ('Domain', 'DOMAIN_NAME')
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
             'type': 'IP'}
        ),
        (
            {'value': '11.11.11.11', 'indicator_type': 100, 'score': 2},
            {'expiration_date': -1, 'indicator': '11.11.11.11', 'reputation': 'SUSPICIOUS', 'severity': 'INFO', 'type': '100'}
        ),
        (
            {'value': '11.11.11.11', 'indicator_type': 'IP'},
            {'expiration_date': -1, 'indicator': '11.11.11.11', 'reputation': 'UNKNOWN', 'severity': 'INFO', 'type': 'IP'}
        ),
        (
            {'value': '11.11.11.11', 'indicator_type': 'IP', 'expiration': '2020-06-03T00:00:00Z'},
            {'expiration_date': 1591142400000, 'indicator': '11.11.11.11', 'reputation': 'UNKNOWN', 'severity': 'INFO', 'type': 'IP'}    # noqa: E501
        ),
        (
            {'value': '11.11.11.11', 'indicator_type': 'IP', 'comments': [{'type': 'IndicatorCommentTimeLine', 'content': 'test'}]},    # noqa: E501
            {'expiration_date': -1, 'indicator': '11.11.11.11', 'reputation': 'UNKNOWN', 'severity': 'INFO', 'type': 'IP'}
        ),
        (
            {'value': '11.11.11.11', 'indicator_type': 'IP', 'comments': [{'type': 'IndicatorCommentRegular', 'content': 'test'}]},    # noqa: E501
            {'expiration_date': -1, 'indicator': '11.11.11.11', 'reputation': 'UNKNOWN', 'severity': 'INFO', 'type': 'IP', 'comment': 'test'}    # noqa: E501
        ),
        (
            {'value': '11.11.11.11', 'indicator_type': 'IP', 'comments': [{'type': 'IndicatorCommentRegular', 'content': 'test'}, {'type': 'IndicatorCommentRegular', 'content': 'this is the comment'}]},    # noqa: E501
            {'expiration_date': -1, 'indicator': '11.11.11.11', 'reputation': 'UNKNOWN', 'severity': 'INFO', 'type': 'IP', 'comment': 'this is the comment'}    # noqa: E501
        ),
        (
            {'value': '11.11.11.11', 'indicator_type': 'IP', 'aggregatedReliability': 'A - Completely reliable'},
            {'expiration_date': -1, 'indicator': '11.11.11.11', 'reputation': 'UNKNOWN', 'severity': 'INFO', 'type': 'IP', 'reliability': 'A'}    # noqa: E501
        ),
        (
            {'value': '11.11.11.11', 'indicator_type': 'IP', 'CustomFields': {'threattypes': {'threatcategory': 'Malware'}}},    # noqa: E501
            {'expiration_date': -1, 'indicator': '11.11.11.11', 'reputation': 'UNKNOWN', 'severity': 'INFO', 'type': 'IP', 'class': 'Malware'}    # noqa: E501
        ),
        (
            {'value': '11.11.11.11', 'indicator_type': 'IP', 'moduleToFeedMap': {'module': {'sourceBrand': 'test', 'score': 2}}},    # noqa: E501
            {'expiration_date': -1, 'indicator': '11.11.11.11', 'reputation': 'UNKNOWN', 'severity': 'INFO', 'type': 'IP', 'vendors': [{'vendor_name': 'test', 'reputation': 'SUSPICIOUS', 'reliability': 'F'}]}    # noqa: E501
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
                    'xdrstatus': 'disabled'
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
                    'xdrstatus': 'disabled'
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
                    'xdrstatus': 'enabled'
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
        mocker.patch.object(demisto, 'searchIndicators', return_value={})
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
            assert output == 'indicators 11.11.11.11 enabled.', f'enable command\n\tprints:  {output}\n\tinstead: indicators 11.11.11.11 enabled.'    # noqa: E501
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
            assert output == 'indicators 11.11.11.11 disabled.', f'disable command\n\tprints:  {output}\n\tinstead: indicators 11.11.11.11 disabled.'    # noqa: E501
            assert disable_ioc.call_count == 1, 'disable command not called'

    def test_sync(self, mocker):
        http_request = mocker.patch.object(Client, 'http_request')
        iocs, data = TestCreateFile.get_all_iocs(TestCreateFile.data_test_create_file_sync, 'json')
        mocker.patch.object(demisto, 'searchIndicators', returnvalue=iocs)
        mocker.patch('XDR_iocs.return_outputs')
        sync(client)
        assert http_request.call_args.args[0] == 'sync_tim_iocs', 'sync command url changed'

    @freeze_time('2020-06-03T02:00:00Z')
    def test_iocs_to_keep(self, mocker):
        http_request = mocker.patch.object(Client, 'http_request')
        iocs, data = TestCreateFile.get_all_iocs(TestCreateFile.data_test_create_file_iocs_to_keep, 'txt')
        mocker.patch.object(demisto, 'searchIndicators', returnvalue=iocs)
        mocker.patch('XDR_iocs.return_outputs')
        iocs_to_keep(client)
        assert http_request.call_args.args[0] == 'iocs_to_keep', 'iocs_to_keep command url changed'

    def test_tim_insert_jsons(self, mocker):
        http_request = mocker.patch.object(Client, 'http_request')
        mocker.patch.object(demisto, 'getIntegrationContext', return_value={'time': '2020-06-03T00:00:00Z'})
        iocs, _ = TestCreateFile.get_all_iocs(TestCreateFile.data_test_create_file_sync, 'json')
        mocker.patch.object(demisto, 'searchIndicators', return_value=iocs)
        mocker.patch('XDR_iocs.return_outputs')
        tim_insert_jsons(client)
        assert http_request.call_args.kwargs['url_suffix'] == 'tim_insert_jsons/', 'tim_insert_jsons command url changed'

    def test_get_changes(self, mocker):
        mocker.patch.object(demisto, 'getIntegrationContext', return_value={'ts': 1591142400000})
        mocker.patch.object(demisto, 'createIndicators')
        mocker.patch.object(demisto, 'searchIndicators', return_value={})
        xdr_res = {'reply': list(map(lambda xdr_ioc: xdr_ioc[0], TestXDRIOCToDemisto.data_test_xdr_ioc_to_demisto))}
        mocker.patch.object(Client, 'http_request', return_value=xdr_res)
        get_changes(client)
        xdr_ioc_to_timeline(list(map(lambda x: str(x[0].get('RULE_INDICATOR')), TestXDRIOCToDemisto.data_test_xdr_ioc_to_demisto)))    # noqa: E501
