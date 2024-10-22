import emoji

import demistomock as demisto
from tempfile import mkdtemp
from AnomaliThreatStreamv3 import main, get_indicators, \
    REPUTATION_COMMANDS, Client, DEFAULT_INDICATOR_MAPPING, \
    FILE_INDICATOR_MAPPING, INDICATOR_EXTENDED_MAPPING, get_model_description, import_ioc_with_approval, \
    import_ioc_without_approval, create_model, update_model, submit_report, add_tag_to_model, file_name_to_valid_string, \
    get_intelligence, search_intelligence, delete_whitelist_entry_command, update_whitelist_entry_note_command, \
    create_whitelist_entry_command, list_whitelist_entry_command, list_import_job_command, list_rule_command, \
    list_user_command, list_investigation_command, create_rule_command, update_rule_command, delete_rule_command, \
    create_investigation_command, update_investigation_command, delete_investigation_command, add_investigation_element_command, \
    approve_import_job_command, search_threat_model_command, create_element_list, \
    add_threat_model_association_command, validate_values_search_threat_model, validate_investigation_action, \
    return_params_of_pagination_or_limit, create_indicators_list, add_indicator_tag_command, remove_indicator_tag_command, \
    clone_ioc_command, edit_classification_job_command
from CommonServerPython import *
import pytest


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def util_tmp_json_file(mock_object, file_name: str):
    tmp_dir = mkdtemp()
    file_name = f'{file_name}.txt'
    file_obj = {
        'name': file_name,
        'path': os.path.join(tmp_dir, file_name)
    }
    with open(file_obj['path'], 'w') as f:
        json.dump(mock_object, f)

    return file_obj


def mock_client():
    return Client(
        base_url='',
        user_name='user',
        api_key='key',
        proxy=False,
        should_create_relationships=True,
        verify=False,
        reliability='B - Usually reliable',
        remote_api=False,
    )


MOCK_OBJECTS = {"objects": [{"srcip": "8.8.8.8", "itype": "mal_ip", "confidence": 50},
                            {"srcip": "1.1.1.1", "itype": "apt_ip"}]}
MOCK_OBJECTS_2 = {
    "objects": [
        {
            "email": "email_test@domain.com",
            "itype": "compromised_email",
            "confidence": 50
        },
        {
            "srcip": "78.78.78.67",
            "classification": "private",
            "itype": "bot_ip",
            "confidence": 50,
            "severity": "low"
        },
        {
            "domain": "szqylwjzq.biz",
            "classification": "private",
            "itype": "mal_domain",
            "confidence": 95,
            "severity": "very-high"
        }
    ],
    "meta": {
        "confidence": 50,
        "classification": "Private",
        "allow_unresolved": True,
        "tags": [
            "test1",
            "test2"
        ]
    }
}

INDICATOR = [{
    "resource_uri": "/api/v2/intelligence/123456789/",
    "status": "active",
    "uuid": "12345678-dead-beef-a6cc-eeece19516f6",
    "value": "www.demisto.com",
}]


class TestReputationCommands:
    """
    Group the Reputation commands test
    """

    def mocked_http_request_ioc(self, method, url_suffix, params=None, data=None, headers=None, files=None, json=None,
                                resp_type='json'):
        if 'associated_with_intelligence' in url_suffix:
            if 'actor' in url_suffix:
                mocked_actor_result = util_load_json('test_data/mocked_actor_response.json')
                return mocked_actor_result
            else:
                mocked_empty_result = util_load_json('test_data/mocked_empty_response.json')
                return mocked_empty_result
        else:
            if params.get('type', '') == DBotScoreType.IP:
                mocked_ioc_file_path = 'test_data/mocked_ip_response.json'
            elif params.get('type', '') == "md5":
                mocked_ioc_file_path = 'test_data/mocked_file_response.json'
            elif params.get('type', '') == DBotScoreType.DOMAIN:
                mocked_ioc_file_path = 'test_data/mocked_domain_response.json'
            else:
                mocked_ioc_file_path = 'test_data/mocked_url_response.json'

            mocked_ioc_result = util_load_json(mocked_ioc_file_path)
            return mocked_ioc_result

    @pytest.mark.parametrize(
        argnames="ioc_type,ioc_value,ioc_context_key",
        argvalues=[
            ('URL', 'https://test.com,https://test_1.com', 'URL(val.Address && val.Address == obj.Address)'),
            ('Domain', 'test.com,test_1.com', 'Domain(val.Address && val.Address == obj.Address)'),
            ('File', '178ba564b39bd07577e974a9b677dfd86ffa1f1d0299dfd958eb883c5ef6c3e1,'
                     '178ba564b39bd07577e974a9b677dfd86ffa1f1d0299dfd958eb883c5ef6c3e1',
             Common.File.CONTEXT_PATH),
            ('IP', '1.1.1.1,2.2.2.2', Common.IP.CONTEXT_PATH)
        ])
    def test_reputation_commands__happy_path(self, mocker, ioc_type, ioc_value, ioc_context_key):
        """
        Given:
            - Indicators for reputation

        When:
            - Call the reputations command

        Then:
            - Validate the expected results was returned
        """

        # prepare
        command = value_key = ioc_type.lower()
        mocked_ioc_file_path = f'test_data/mocked_{command}_response.json'
        mocked_ioc_result = util_load_json(mocked_ioc_file_path)

        mocker.patch.object(Client, 'http_request', side_effect=self.mocked_http_request_ioc)
        mocker.patch.object(demisto, 'args', return_value={value_key: ioc_value, 'status': 'active',
                                                           'threat_model_association': 'True'})
        mocker.patch.object(demisto, 'command', return_value=command)
        mocker.patch.object(demisto, 'results')

        # run
        main()

        # validate
        iocs = ioc_value.split(',')
        mocked_ioc = mocked_ioc_result['objects'][0]
        for i in range(len(iocs)):
            command_result = demisto.results.call_args_list[i][0][0]
            threat_stream_context = command_result['EntryContext'][f'ThreatStream.{ioc_context_key}']
            human_readable, contents = command_result['HumanReadable'], command_result['Contents']

            expected_values = (DEFAULT_INDICATOR_MAPPING if ioc_type != 'File' else FILE_INDICATOR_MAPPING).values()

            assert all(expected_value in threat_stream_context for expected_value in expected_values)
            assert f'{ioc_type} reputation for: {iocs[i]}' in human_readable
            assert mocked_ioc == contents
            assert isinstance(command_result['Relationships'], list)
            for entry in command_result['Relationships']:
                assert entry.get('entityBType') == 'Threat Actor'

    def mocked_http_request(self, method, url_suffix, params=None, data=None, headers=None, files=None, json=None,
                            resp_type='json'):
        if 'actor' in url_suffix:
            mocked_actor_result = util_load_json('test_data/mocked_actor_response.json')
            return mocked_actor_result
        else:
            mocked_empty_result = util_load_json('test_data/mocked_empty_response.json')
            return mocked_empty_result

    def test_get_intelligence_command(self, mocker):
        """
        Given:
            - Client, indicator, and indicator type

        When:
            - Call the get_intelligence command


        Then:
            - Validate that the outputs and the relationship were created
        """

        # prepare
        mocker.patch.object(Client, 'http_request', side_effect=self.mocked_http_request)
        client = mock_client()

        # run
        intelligence_relationships, outputs = get_intelligence(client, INDICATOR[0], FeedIndicatorType.URL)

        # validate
        assert outputs.get('Actor')
        assert not outputs.get('Campaign')
        assert intelligence_relationships

    @pytest.mark.parametrize("should_create_relationships", [(True), (False)])
    def test_get_intelligence_with_false_create_relationships(self, mocker, should_create_relationships):
        """
        Given:
            - Client with should_create_relationships=False, indicator, and indicator type

        When:
            - Call the get_intelligence command

        Then:
            - Validate that the relatiionships list contains only EntityRelationship objects
        """

        # prepare
        mocker.patch.object(Client, 'http_request', side_effect=self.mocked_http_request)
        client = Client(base_url='',
                        user_name='',
                        api_key='',
                        proxy=False,
                        should_create_relationships=should_create_relationships,
                        verify=False,
                        reliability='B - Usually reliable',
                        remote_api=False,
                        )

        # run
        intelligence_relationships, _ = get_intelligence(client, INDICATOR[0], FeedIndicatorType.URL)

        # validate
        assert isinstance(intelligence_relationships, list)
        for entry in intelligence_relationships:
            assert isinstance(entry, EntityRelationship)

    @pytest.mark.parametrize(
        argnames='confidence, threshold, exp_dbot_score',
        argvalues=[(20, None, Common.DBotScore.GOOD),
                   (30, None, Common.DBotScore.SUSPICIOUS),
                   (70, None, Common.DBotScore.BAD),
                   (30, 50, Common.DBotScore.GOOD),
                   (60, 50, Common.DBotScore.BAD),
                   (70, 80, Common.DBotScore.GOOD),
                   (20, 10, Common.DBotScore.BAD)])
    def test_ioc_reputation_with_thresholds_in_command(self, mocker, confidence, threshold, exp_dbot_score):
        """
        Given
            - Various thresholds levels

        When
            - Run the reputation commands

        Then
            - Validate the dbot score was rated according to the threshold
             and Malicious key defined for the generic reputation in case confidence > theshold
        """

        # prepare

        test_indicator = {'confidence': confidence, 'value': 'test_ioc', 'asn': '', 'meta': {'registrant_name': 'test'}}
        mocker.patch.object(demisto, 'results')
        mocker.patch('AnomaliThreatStreamv3.search_worst_indicator_by_params', return_value=test_indicator)

        for ioc in REPUTATION_COMMANDS:
            ioc_arg_name = ioc if ioc != 'threatstream-email-reputation' else 'email'
            mocker.patch.object(demisto, 'args', return_value={ioc_arg_name: 'test_ioc', 'threshold': threshold})
            mocker.patch.object(demisto, 'command', return_value=ioc)

            # run
            main()

            # validate
            entry_context = demisto.results.call_args[0][0]['EntryContext']
            assert entry_context[Common.DBotScore.CONTEXT_PATH][0]['Score'] == exp_dbot_score
            if exp_dbot_score == Common.DBotScore.BAD and ioc_arg_name != 'email':  # email is not a generic reputation
                assert 'Malicious' in json.dumps(entry_context)

    @pytest.mark.parametrize(argnames='threshold_in_command, threshold_in_params, exp_dbot_score',
                             argvalues=[(None, None, Common.DBotScore.SUSPICIOUS),
                                        (50, None, Common.DBotScore.BAD),
                                        (None, 50, Common.DBotScore.BAD),
                                        (60, 40, Common.DBotScore.GOOD),
                                        (40, 60, Common.DBotScore.BAD)])
    def test_ioc_reputation_with_thresholds_in_instance_param(self, mocker,
                                                              threshold_in_command,
                                                              threshold_in_params,
                                                              exp_dbot_score):
        """
        Given
            - Thresholds levels defined for each ioc in the instance params and confidence are 55

        When
            - Run the reputation commands

        Then
            - Validate the dbot score was rated according to the threshold in the command
             and only if not defined in the command will rate according the instance param
        """

        # prepare

        test_indicator = {'confidence': 55,
                          'value': 'test_ioc',
                          'asn': 'test_asn',
                          'org': 'test_org',
                          'tlp': 'test_tlp',
                          'country': 'test_country',
                          'meta': {'registrant_name': 'test', 'maltype': 'test_maltype'}}
        mocker.patch.object(demisto, 'results')
        mocker.patch('AnomaliThreatStreamv3.search_worst_indicator_by_params', return_value=test_indicator)

        for ioc in ['ip', 'domain', 'file', 'url']:
            mocker.patch.object(demisto, 'args', return_value={ioc: 'test_ioc', 'threshold': threshold_in_command})
            mocker.patch.object(demisto, 'command', return_value=ioc)
            # THRESHOLDS_FROM_PARAM[ioc] = threshold_in_params
            mocker.patch.object(demisto, 'params', return_value={f'{ioc}_threshold': threshold_in_params})

            # run
            main()

            # validate
            entry_context = demisto.results.call_args[0][0]['EntryContext']
            assert entry_context[Common.DBotScore.CONTEXT_PATH][0]['Score'] == exp_dbot_score
            if exp_dbot_score == Common.DBotScore.BAD:
                assert 'Malicious' in json.dumps(entry_context)

    @pytest.mark.parametrize(argnames='include_inactive, exp_status_param',
                             argvalues=[('true', 'active,inactive'), ('false', 'active')])
    def test_get_active_and_inactive_ioc(self, mocker, include_inactive, exp_status_param):
        """
            Given
                - The Include inactive results flag is true/false

            When
                - Run the reputation commands

            Then
                - Validate inactive result returned/not returned
            """

        # prepare
        mocked_search = mocker.patch('AnomaliThreatStreamv3.search_worst_indicator_by_params', return_value=None)
        mocker.patch.object(demisto, 'params', return_value={'include_inactive': include_inactive})

        for ioc, value in [('ip', '8.8.8.8'), ('domain', 'google.com'),
                           ('file', 'd26cec10398f2b10202d23c966022dce'),
                           ('url', 'www.google.com')]:
            mocker.patch.object(demisto, 'command', return_value=ioc)
            mocker.patch.object(demisto, 'args', return_value={ioc: value})

            # run
            main()

        # validate
        assert mocked_search.call_args[0][1]['status'] == exp_status_param

    def test_no_confidence_in_result_ioc(self, mocker):
        """
        Given
            - Indicator form ThreatStream without confidence value

        When
            - Run the reputation command

        Then
            - Validate the DbotScore was set to 1
        """

        # prepare
        test_indicator = {'value': 'test_ioc', 'asn': '', 'meta': {'registrant_name': 'test'}}
        mocker.patch.object(demisto, 'results')
        mocker.patch('AnomaliThreatStreamv3.search_worst_indicator_by_params', return_value=test_indicator)

        for ioc in REPUTATION_COMMANDS:
            ioc_arg_name = ioc if ioc != 'threatstream-email-reputation' else 'email'
            mocker.patch.object(demisto, 'args', return_value={ioc_arg_name: 'test_ioc'})
            mocker.patch.object(demisto, 'command', return_value=ioc)

            # run
            main()

            # validate
            entry_context = demisto.results.call_args[0][0]['EntryContext']
            assert entry_context[Common.DBotScore.CONTEXT_PATH][0]['Score'] == Common.DBotScore.GOOD


class TestImportCommands:
    """
    Group the import commands test
    """

    @pytest.mark.parametrize(argnames='import_type', argvalues=['file-id', 'test-import-type'])
    def test_import_indicator_with_approval__happy_path(self, mocker, import_type):
        """
        Given:
            - Indicator to import with approval

        When:
            - Call the import with approval command

        Then:
            - Validate the request and response are as expected
        """

        # prepare
        mocked_file_path = util_tmp_json_file(MOCK_OBJECTS, 'test_file')
        mocker.patch.object(demisto, 'getFilePath', return_value=mocked_file_path)
        mocker.patch.object(Client, 'http_request',
                            return_value={'success': True, 'import_session_id': 'test_session_id', 'job_id': 'id'})

        # run
        result = import_ioc_with_approval(mock_client(), import_type, 'test_value', tags="tag1,tag2",
                                          expiration_ts="2023-12-25T00:00:00")

        # validate

        files = Client.http_request.call_args[1]['files']
        data = Client.http_request.call_args[1]['data']

        if files:  # in case of import_type=file-id
            assert files['file'][0] == 'test_file.txt'
        else:
            assert data[import_type] == 'test_value'
            assert data['expiration_ts'] == '2023-12-25T00:00:00'
            assert data['tags'] == '[{"name": "tag1"}, {"name": "tag2"}]'

        assert all(key in data for key in ['classification', 'confidence', 'threat_type', 'severity', 'default_state'])

        assert result.outputs == {'ImportID': 'test_session_id', 'JobID': 'id'}

    @pytest.mark.parametrize(
        'mock_object, file_name, args, expected_meta_data_keys, expected_meta_data_changed',
        [
            (
                MOCK_OBJECTS,
                'test_file',
                {
                    'file_id': 'test_file_id',
                    'classification': 'Private',
                    'confidence': "50",
                    'severity': 'low',
                    'allow_unresolved': True
                },
                ('classification', 'confidence', 'severity', 'allow_unresolved'),
                {
                    'classification': 'Private',
                    'confidence': 50,
                    'severity': 'low',
                    'allow_unresolved': True
                }
            ),
            (
                MOCK_OBJECTS_2,
                'test_file',
                {
                    'file_id': 'test_file_id',
                    'classification': 'Private',
                    'confidence': "70",
                    'severity': 'high',
                    'allow_unresolved': True
                },
                ('classification', 'confidence', 'severity', 'allow_unresolved', 'tags'),
                {'severity': 'high', 'confidence': 70}
            ),
            (
                MOCK_OBJECTS_2,
                'test_file',
                {
                    'file_id': 'test_file_id',
                    'classification': 'Private',
                    'confidence': "70",
                    'severity': 'high',
                    'allow_unresolved': True,
                    'tags': "tag1,tag2",
                    "tags_tlp": "Red"
                },
                ('classification', 'confidence', 'severity', 'allow_unresolved', 'tags'),
                {'severity': 'high', 'confidence': 70, 'tags': [{'name': 'tag1', 'tlp': 'red'}, {'name': 'tag2', 'tlp': 'red'}]}
            ),
            (
                MOCK_OBJECTS_2,
                'test_file',
                {
                    'file_id': 'test_file_id',
                    'classification': 'Private',
                    'confidence': "70",
                    'severity': 'high',
                    'allow_unresolved': True,
                    'tags': "tag1,tag2",
                },
                ('classification', 'confidence', 'severity', 'allow_unresolved', 'tags'),
                {'severity': 'high', 'confidence': 70, 'tags': [{'name': 'tag1'}, {'name': 'tag2'}]}
            )
        ]
    )
    def test_import_indicator_without_approval__happy_path(self,
                                                           mocker,
                                                           mock_object: dict,
                                                           file_name: str,
                                                           args: dict,
                                                           expected_meta_data_keys: tuple,
                                                           expected_meta_data_changed: dict):
        """
        Given:
            - Indicator to import without approval

        When:
            - Call the import without approval command

        Then:
            - Validate the request and response are as expected
        """

        # prepare
        mocked_file_path = util_tmp_json_file(mock_object, file_name)
        mocker.patch.object(demisto, 'getFilePath', return_value=mocked_file_path)
        mocker.patch.object(Client, 'http_request')

        # run
        result = import_ioc_without_approval(
            mock_client(),
            file_id=args['file_id'],
            classification=args['classification'],
            confidence=args.get('confidence'),
            severity=args.get('severity'),
            allow_unresolved=args.get('allow_unresolved'),
            tags=args.get('tags'),
            tags_tlp=args.get('tags_tlp'),
        )

        # validate
        json_data = Client.http_request.call_args[1]['json']['meta']
        assert set(expected_meta_data_keys).issubset(json_data.keys())
        for key in expected_meta_data_changed:
            assert json_data[key] == expected_meta_data_changed[key]
        assert result == 'The data was imported successfully.'

    @pytest.mark.parametrize(argnames='command', argvalues=[import_ioc_with_approval, import_ioc_without_approval])
    def test_import_indicator__invalid_file_id(self, mocker, command):
        """
        Given:
            - Mock getFilePath to raise Exception as file id not existWrong file id to import as IOC data

        When:
            - Call import commands with file-id as import_type

        Then:
            - Validate DemistoException was raised
        """

        # prepare
        mocker.patch.object(demisto, 'getFilePath', side_effect=lambda *args, **kwargs: open('wrong_file_id'))

        # run & validate
        msg = 'ThreatStream - Entry file-id does not contain a file.'
        with pytest.raises(DemistoException, match=msg):
            command(mock_client(), 'file-id', 'file-id')

    def test_import_indicator_with_approval__fail_import(self, mocker):
        """
        Given:
            - Import response returned with field indicating that the import fail

        When:
            - Call the import with approval command

        Then:
            - Validate DemistoException was raised
        """

        # prepare
        mocker.patch.object(Client, 'http_request', return_value={'success': False})

        # run & validate
        msg = 'The data was not imported. Check if valid arguments were passed'
        with pytest.raises(DemistoException, match=msg):
            import_ioc_with_approval(mock_client(), 'test_import_type', 'test_value')


class TestGetCommands:
    """
    Group the 'get' commands test
    """

    @staticmethod
    def mocked_http_get_response(command, **kwargs):
        mocked_file_path = 'test_data/mocked_get_commands_response.json'
        mocked_data = util_load_json(mocked_file_path)[command]
        if 'resp_type' in kwargs:
            mocked_response = requests.Response()
            mocked_response._content = json.dumps(mocked_data).encode('utf-8')
            mocked_response.status_code = 200
            return mocked_response

        return mocked_data

    @staticmethod
    def mocked_http_get_not_found_response(*args, **kwargs):
        if 'resp_type' in kwargs:
            mocked_response = requests.Response()
            mocked_response.status_code = 404
            return mocked_response

        return {}

    commands_with_expected_context_key = [
        ('threatstream-get-analysis-status', {'report_id': 1}, ['ReportID', 'Status', 'Platform', 'Verdict']),
        ('threatstream-get-passive-dns', {'value': 'test'}, ['Domain', 'Rrtype', 'Source', 'FirstSeen']),
        ('threatstream-get-model-list', {'model': 'Actor'}, ['Name', 'ID', 'CreatedTime', 'Type']),
        ('threatstream-get-model-description', {'model': 'Actor', 'id': 'test'}, ['File', 'FileID']),
        ('threatstream-get-indicators-by-model', {'model': 'Actor', 'id': 1}, ['ModelType', 'ModelID', 'Indicators']),
        ('threatstream-get-indicators', {}, INDICATOR_EXTENDED_MAPPING.keys()),
        ('threatstream-supported-platforms', {}, ['Platform', 'Name', 'Types', 'Label']),
        ('threatstream-analysis-report', {'report_id': 1}, ['Category', 'Started', 'ReportID', 'Verdict', 'Network'])
    ]

    commands_with_expected_output = [
        ('threatstream-get-analysis-status', {'report_id': 1}, 'No report found with id 1'),
        ('threatstream-get-passive-dns', {'value': 'test_val'}, 'No Passive DNS enrichment data found for test_val'),
        ('threatstream-get-model-list', {'model': 'Actor'}, 'No Threat Model Actor found.'),
        ('threatstream-get-model-description', {'model': 'Actor', 'id': 1},
         'No description found for Threat Model Actor with id 1'),
        ('threatstream-get-indicators-by-model', {'model': 'Actor', 'id': 1},
         'No indicators found for Threat Model Actor with id 1'),
        ('threatstream-get-indicators', {}, 'No indicators found from ThreatStream'),
        ('threatstream-supported-platforms', {}, 'No supported platforms found for default sandbox'),
        ('threatstream-analysis-report', {'report_id': 1}, 'No report found with id 1')
    ]

    @pytest.mark.parametrize(
        argnames='command, command_args, expected_context_keys',
        argvalues=commands_with_expected_context_key)
    def test_get_commands__happy_path(self, mocker, command, command_args, expected_context_keys):
        """
        Given:
            - Command made get request in ThreatStream with args

        When:
            - Run this command

        Then:
            - Validate expected result was returned
        """

        # prepare
        mocker.patch.object(
            Client, 'http_request',
            side_effect=lambda *args, **kwargs: self.mocked_http_get_response(command, **kwargs)
        )
        mocker.patch.object(demisto, 'args', return_value=command_args)
        mocker.patch.object(demisto, 'command', return_value=command)
        mocker.patch.object(demisto, 'results')
        mocker.patch('AnomaliThreatStreamv3.fileResult', return_value={'File': 'test_name', 'FileID': 'test_id'})

        # run
        main()

        # validate
        result = demisto.results.call_args[0][0]
        context = result['EntryContext'].popitem()[1] if 'EntryContext' in result else result
        if isinstance(context, list):
            context = context[0]
        assert all(key in context for key in expected_context_keys)

    @pytest.mark.parametrize(
        argnames='command, command_args, expected_output',
        argvalues=commands_with_expected_output)
    def test_get_commands__no_result(self, mocker, command, command_args, expected_output):
        """
        Given:
            - ThreatStream return nothing for the get requests

        When:
            -Run commands made get request

        Then:
            - Validate the expected message was returned
        """

        # prepare
        mocker.patch.object(Client, 'http_request', side_effect=self.mocked_http_get_not_found_response)
        mocker.patch.object(demisto, 'args', return_value=command_args)
        mocker.patch.object(demisto, 'command', return_value=command)
        mocker.patch.object(demisto, 'results')

        # run
        main()

        # validate
        result = demisto.results.call_args[0][0]
        assert result == expected_output

    @pytest.mark.parametrize(
        argnames='command, command_args, expected_http_params',
        argvalues=[
            ('threatstream-get-model-list', {'model': 'Actor'},
             {'limit': 50, 'skip_intelligence': "true", 'skip_associations': "true", 'order_by': "-created_ts"}),
            ('threatstream-get-model-description', {'model': 'Actor', 'id': 1},
             {'skip_intelligence': "true", 'skip_associations': "true"}),
            ('threatstream-get-indicators-by-model', {'model': 'Actor', 'id': 1}, {'limit': 20}),
            ('threatstream-get-indicators-by-model', {'model': 'Actor', 'id': 1, 'page': 2, 'page_size': 2},
             {'limit': 2, 'offset': 2}),
            ('threatstream-get-indicators', {}, {'limit': 20}),
            ('threatstream-get-indicators', {'page': 2, 'page_size': 2}, {'limit': 2, 'offset': 2}),
            ('threatstream-list-user', {'page': 2, 'page_size': 3}, {'limit': 3, 'offset': 3}),
            ('threatstream-list-user', {}, {'limit': 50}),
            ('threatstream-list-investigation', {'page': 3, 'page_size': 2},
             {'limit': 2, 'offset': 4, 'order_by': '-created_ts'}),
            ('threatstream-list-investigation', {}, {'limit': 50, 'order_by': '-created_ts'}),
            ('threatstream-list-rule', {'page': 2, 'page_size': 2}, {'limit': 2, 'offset': 2, 'order_by': '-created_ts'}),
            ('threatstream-list-rule', {}, {'limit': 50, 'order_by': '-created_ts'}),
            ('threatstream-list-whitelist-entry', {'page': 2, 'page_size': 4},
             {'limit': 4, 'offset': 4, 'order_by': '-created_ts', 'format': 'json', 'showNote': 'true'}),
            ('threatstream-list-whitelist-entry', {},
             {'limit': 50, 'format': 'json', 'showNote': 'true', 'order_by': '-created_ts'}),
            ('threatstream-list-import-job', {'page': 2, 'page_size': 4}, {'limit': 4, 'offset': 4}),
            ('threatstream-list-import-job', {}, {'limit': 50}),
            ('threatstream-list-import-job', {'page': 2, 'page_size': 4, 'status_in': 'Errors'},
             {'limit': 4, 'offset': 4, 'status': 'errors'}),
            ('threatstream-list-import-job', {'page': 2, 'page_size': 4, 'status_in': 'Approved'},
             {'limit': 4, 'offset': 4, 'status': 'approved'}),
            ('threatstream-list-import-job', {'page': 2, 'page_size': 4, 'status_in': 'Ready To Review'},
             {'limit': 4, 'offset': 4, 'status': 'done'}),
            ('threatstream-list-import-job', {'page': 2, 'page_size': 4, 'status_in': 'Rejected'},
             {'limit': 4, 'offset': 4, 'status': 'deleted'}),
            ('threatstream-list-import-job', {'page': 2, 'page_size': 4, 'status_in': 'Processing'},
             {'limit': 4, 'offset': 4, 'status': 'processing'}),
        ]
    )
    def test_expected_params_in_get_requests(self, mocker, command, command_args, expected_http_params):
        """
        Given:
            - Commands send custom params to http requests

        When:
            - Call those commands

        Then:
            - Validate the expected params was sent
        """

        # prepare
        mocker.patch.object(Client, 'http_request', side_effect=self.mocked_http_get_not_found_response)
        mocker.patch.object(demisto, 'args', return_value=command_args)
        mocker.patch.object(demisto, 'command', return_value=command)

        # run
        main()

        # validate
        assert expected_http_params == Client.http_request.call_args[1]['params']

    @pytest.mark.parametrize(
        argnames='model, description',
        argvalues=[
            ('signature', {'notes': 'test_description'}),
            ('tipreport', {'body': 'test_description'}),
            ('actor', {'description': 'test_description'})
        ])
    def test_get_model_description__various_models(self, mocker, model, description):
        """
        Given:
            - Various Threat models with description

        When:
            - Call get_model_description

        Then:
            - Validate the expected description was returned
        """

        # prepare
        mocked_response = requests.Response()
        mocked_response._content = json.dumps(description).encode('utf-8')
        mocker.patch.object(Client, 'http_request', return_value=mocked_response)
        mocked_result = mocker.patch('AnomaliThreatStreamv3.fileResult')

        # run
        get_model_description(mock_client(), model, '1')

        # validate
        assert mocked_result.call_args[0][1] == b'test_description'


class TestUpdateCommands:
    """
    Group the 'update' commands test
    """

    def test_create_model__happy_path(self, mocker):
        """
        Given:
            - Threat Model to be created

        When:
            - Run the create_model command

        Then:
            - Validate results return as expected
        """

        # prepare
        model_id = 'test_model_id'
        mocker.patch.object(Client, 'http_request', return_value={'id': 'test_id'})
        mocker.patch('AnomaliThreatStreamv3.get_iocs_by_model', return_value=model_id)

        # run
        created_model_id = create_model(mock_client(), model='Actor', name='test_actor', tags='tag_1,tag_2',
                                        description='test_desc')

        # validate
        data = Client.http_request.call_args[1]['data']
        data = json.loads(data)
        assert data['tags'][1] == 'tag_2'
        assert data['description'] == 'test_desc'
        assert created_model_id == model_id

    def test_update_model__happy_path(self, mocker):
        """
        Given:
            - Threat Model to be updated

        When:
            - Run the update_model command

        Then:
            - Validate results return as expected
        """

        # prepare
        model_id = 'test_model_id'
        mocker.patch.object(Client, 'http_request')
        mocker.patch('AnomaliThreatStreamv3.get_iocs_by_model', return_value=model_id)

        # run
        updated_model_id = update_model(
            mock_client(),
            model='Actor',
            model_id=model_id,
            name='test_actor',
            tags='tag_1,updated_tag_2',
        )

        # validate
        data = Client.http_request.call_args[1]['data']
        data = json.loads(data)
        assert data['tags'][1] == 'updated_tag_2'
        assert updated_model_id == model_id

    def test_create_model__creation_failed(self, mocker):
        """
        Given:
            - Threat Model to create - fail

        When:
            - Run create_model command

        Then:
            - Validate the result are as expected
        """

        # prepare
        mocker.patch.object(Client, 'http_request', return_value={})

        # run & validate
        msg = 'Actor Threat Model was not created. Check the input parameters'
        with pytest.raises(DemistoException, match=msg):
            create_model(mock_client(), model='Actor', name='test_actor')

    def test_submit_url_report__happy_path(self, mocker):
        """
        Given:
            - test url to submit for report

        When:
            - Call the submit report command

        Then:
            - Validate the result are as expected
        """

        # prepare
        mocked_report = {'success': True, 'reports': {'test_platform': {'id': 'report_id'}}}
        mocker.patch.object(Client, 'http_request', return_value=mocked_report)
        mocker.patch('AnomaliThreatStreamv3.get_submission_status', return_value=('success', None))

        # run
        submit_result = submit_report(
            mock_client(),
            submission_type='url',
            submission_value='https://test.com',
            report_platform='test_platform',
        )

        # validate
        expected_data_keys = [
            'report_radio-classification', 'report_radio-platform', 'use_premium_sandbox', 'report_radio-url'
        ]
        assert all(key in Client.http_request.call_args[1]['data'] for key in expected_data_keys)
        assert all(key in submit_result.outputs for key in ['ReportID', 'Status', 'Platform'])

    def test_submit_file_report__happy_path(self, mocker):
        """
        Given:
            - Test json file to submit for report

        When:
            - Call the submit report command with json file

        Then:
            - Validate the result are as expected
        """

        # prepare
        file_obj = util_tmp_json_file(MOCK_OBJECTS, 'test_file')
        mocker.patch.object(demisto, 'getFilePath', return_value=file_obj)
        mocked_report = {'success': True, 'reports': {'test_platform': {'id': 'report_id'}}}
        mocker.patch.object(Client, 'http_request', return_value=mocked_report)
        mocker.patch('AnomaliThreatStreamv3.get_submission_status', return_value=('success', None))

        # run
        submit_result = submit_report(
            mock_client(),
            submission_type='file',
            submission_value='file',
            report_platform='test_platform',
        )

        # validate
        expected_data_keys = ['report_radio-classification', 'report_radio-platform', 'use_premium_sandbox']
        assert 'report_radio-file' in Client.http_request.call_args[1]['files']
        assert all(key in Client.http_request.call_args[1]['data'] for key in expected_data_keys)
        assert all(key in submit_result.outputs for key in ['ReportID', 'Status', 'Platform'])

    def test_submit_file_report__invalid_file(self, mocker):
        """
        Given:
            - Invalid test json file to submit for report

        When:
            - Call the submit report command with json file

        Then:
            - Validate the result are as expected
        """

        # prepare
        mocker.patch.object(demisto, 'getFilePath', side_effect=lambda *args, **kwargs: open('wrong_path', 'rb'))
        mocked_report = {'success': True, 'reports': {'test_platform': {'id': 'report_id'}}}
        mocker.patch.object(Client, 'http_request', return_value=mocked_report)
        mocker.patch('AnomaliThreatStreamv3.get_submission_status', return_value=('success', None))

        # run & validate
        msg = 'ThreatStream - Entry file_value does not contain a file.'
        with pytest.raises(DemistoException, match=msg):
            submit_report(
                mock_client(),
                submission_type='file',
                submission_value='file_value',
                report_platform='test_platform',
            )

    def test_add_tag_to_model__happy_path(self, mocker):
        """
        Given:
            - Tags to add to a Threat Model

        When:
            - Call to add tag to model command

        Then:
            - Validate the result are as expected
        """

        # prepare
        mocker.patch.object(Client, 'http_request', return_value={'success': True})

        # run
        res = add_tag_to_model(mock_client(), model_id='test_actor_id', model='Actor', tags='tag_1,tag_2')

        # validate
        data = json.loads(Client.http_request.call_args[1]['data'])

        assert data['tags'][1] == {'name': 'tag_2', 'tlp': 'red'}
        assert res == "Added successfully tags: ['tag_1', 'tag_2'] to Actor with test_actor_id"

    def test_add_tag_to_model__not_exist_model(self, mocker):
        """
        Given:
            - Tags to add to an Invalid Threat Model

        When:
            - Call to add tag to model command

        Then:
            - Validate the result are as expected
        """

        # prepare
        mocker.patch.object(Client, 'http_request', return_value={'success': False})

        # run & validate
        msg = "Failed to add \['tag_1'\] to Actor with test_actor_id"
        with pytest.raises(DemistoException, match=msg):
            add_tag_to_model(mock_client(), model_id='test_actor_id', model='Actor', tags='tag_1')


def test_emoji_handling_in_file_name():
    file_names_package = ['Fwd for you 😍', 'Hi all', '', '🐝🤣🇮🇱👨🏽‍🚀🧟‍♂🧞‍♂🧚🏼‍♀', '🧔🤸🏻‍♀🥩🧚😷🍙👻']

    for file_name in file_names_package:
        demojized_file_name = file_name_to_valid_string(file_name)
        assert demojized_file_name == emoji.demojize(file_name)
        assert not emoji.emoji_count(file_name_to_valid_string(demojized_file_name))


class TestGetIndicators:
    @staticmethod
    def test_sanity(mocker):
        """
        Given
            a limit above the number of available indicators
        When
            calling the get_indicator command
        Then
            verify that the maximum available amount is returned.
        """
        mocker.patch.object(Client, 'http_request', side_effect=[
            {'objects': INDICATOR * 50},
            {'objects': []},
        ])
        client = Client(
            base_url='',
            user_name='',
            api_key='',
            verify=False,
            proxy=False,
            reliability='B - Usually reliable',
            should_create_relationships=False,
            remote_api=False,
        )

        results = get_indicators(client, limit='7000')

        assert len(results.outputs) == 50

    @staticmethod
    def test_pagination(mocker):
        """
        Given
            a limit above the page size
        When
            calling the get_indicator command
        Then
            verify that the requested amount is returned.
        """
        mocker.patch.object(Client, 'http_request', side_effect=[
            {'objects': INDICATOR * 1000, 'meta': {'next': '/api/v2/intelligence/?&search_after=1693750222045%2C455231625'}},
            {'objects': INDICATOR * 1000, 'meta': {'next': '/api/v2/intelligence/?&search_after=1693750222045%2C455231625'}},
            {'objects': INDICATOR * 1000, 'meta': {'next': '/api/v2/intelligence/?&search_after=1693750222045%2C455231625'}},
            {'objects': INDICATOR * 1000, 'meta': {'next': '/api/v2/intelligence/?&search_after=1693750222045%2C455231625'}},
            {'objects': INDICATOR * 1000, 'meta': {'next': '/api/v2/intelligence/?&search_after=1693750222045%2C455231625'}},
            {'objects': INDICATOR * 1000, 'meta': {'next': '/api/v2/intelligence/?&search_after=1693750222045%2C455231625'}},
            {'objects': INDICATOR * 1000, 'meta': {'next': None}},
        ])
        client = Client(
            base_url='',
            user_name='',
            api_key='',
            verify=False,
            proxy=False,
            reliability='B - Usually reliable',
            should_create_relationships=False,
            remote_api=False,
        )

        results = get_indicators(client, limit='7000')

        assert len(results.outputs) == 7000

    @staticmethod
    def test_pagination_without_credentials(mocker):
        """
        Given
            - An on-prem user
        When
            - Calling the get_indicator command
            - The 'next' url is expected to have credentials from the response
        Then
            - Verify the first API call is made with credentials
            - Verify the second API call is made without credentials
        """
        http_request = mocker.patch.object(Client, 'http_request', side_effect=[
            {'objects': INDICATOR * 1000, 'meta': {'next': '/api/v2/intelligence/?&search_after=test&api_key=test'}},
            {'objects': INDICATOR * 1000, 'meta': {'next': None}},
        ])
        client = Client(
            base_url='',
            user_name='',
            api_key='',
            verify=False,
            proxy=False,
            reliability='B - Usually reliable',
            should_create_relationships=False,
            remote_api=False,
        )

        _ = get_indicators(client, limit='7000')

        assert not http_request.call_args_list[0].kwargs.get("without_credentials")
        assert http_request.call_args_list[1].kwargs["without_credentials"]


def test_search_intelligence(mocker):
    """
    Given:
        - Various parameters to search intelligence by

    When:
        - Call search_intelligence command

    Then:
        - Validate the expected values was returned
    """

    # prepare

    mocked_ip_result = util_load_json('test_data/mocked_ip_response.json')
    mocker.patch.object(Client, 'http_request', return_value=mocked_ip_result)

    args = {'uuid': '9807794e-3de0-4340-91ca-cd82dd7b6d24',
            'itype': 'apt_ip'}
    client = mock_client()

    # run
    result = search_intelligence(client, **args)

    assert result.outputs[0].get('itype') == 'c2_ip'
    assert result.outputs_prefix == 'ThreatStream.Intelligence'


def test_search_intelligence_with_confidence(mocker):
    """

    Given:
        - Various parameters to search intelligence by

    When:
        - Call search_intelligence command

    Then:
        - Validate the params passed correctly

    """
    mocked_ip_result = util_load_json('test_data/mocked_ip_response.json')
    mocker.patch.object(Client, 'http_request', return_value=mocked_ip_result)

    args = {'uuid': '9807794e-3de0-4340-91ca-cd82dd7b6d24',
            'confidence': 'lt 80'}
    client = mock_client()
    search_intelligence(client, **args)
    http_call_args = client.http_request.call_args.kwargs.get('params')
    assert 'confidence' not in http_call_args
    assert 'confidence__lt' in http_call_args


def test_delete_whitelist_entry_command(mocker):
    """

    Given:
        - Entry id to delete

    When:
        - Call threatstream-delete-whitelist-entry command

    Then:
        - Validate command result readable output

    """
    mocker.patch.object(Client, 'http_request', return_value=None)

    args = {'entry_id': '77'}
    client = mock_client()
    command_result = delete_whitelist_entry_command(client, **args)
    assert command_result.readable_output == 'The entity was deleted successfully'


def test_update_whitelist_entry_note_command(mocker):
    """

    Given:
        -  Entry id to update and a note

    When:
        - Call threatstream-list-whitelist-entry command

    Then:
        - Validate command result readable output

    """
    mocker.patch.object(Client, 'http_request', return_value=None)

    args = {'entry_id': '66',
            'note': 'some_note'}
    client = mock_client()
    command_result = update_whitelist_entry_note_command(client, **args)
    assert command_result.readable_output == 'The note was updated successfully.'


@pytest.mark.parametrize('args', [
    ({'domains': 'example.com'}),
    ({'entry_id': 'xxxx-xxxxx'}),
])
def test_create_whitelist_entry_command(mocker, args):
    """

    Given:
        -  Domain

    When:
        - Call threatstream-create-whitelist-entry command

    Then:
        - Validate command result readable output

    """
    mocker.patch.object(Client, 'http_request', return_value={"message": "Created 1 item(s).", "success": True})
    mocker_file_get = mocker.patch.object(demisto, 'getFilePath', return_value={'id': 'xxx',
                                                                                'path': 'test/test.txt', 'name': 'test.txt'})
    mocker_file_open = mocker.patch("builtins.open", return_value="file_data")
    client = mock_client()
    command_result = create_whitelist_entry_command(client, **args)
    if 'entry_id' in args:
        assert mocker_file_get.call_count == 1
        assert mocker_file_open.call_count == 1
    assert command_result.readable_output == "Created 1 item(s)."


def test_list_whitelist_entry_command(mocker):
    """

    Given:
        - Format parameter to retrive results by

    When:
        - Call threatstream-list-whitelist-entry command

    Then:
        - Validate the command result

    """
    mocked_response = util_load_json('test_data/mocked_data.json').get('list_whitelist_response')
    mocker.patch.object(Client, 'http_request', return_value=mocked_response)

    args = {'format': 'JSON'}
    client = mock_client()
    command_result = list_whitelist_entry_command(client, **args)
    assert command_result.readable_output == '### Whitelist entries\n' \
                                             '|Id|Value|Resource Uri|Created At|Modified At|Value Type|Notes|\n|' \
                                             '---|---|---|---|---|---|---|\n|' \
                                             ' 13 | example.com | resource_uri | 2023-02-21T19:59:02.091404 |' \
                                             ' 2023-02-21T19:59:02.091404 | domain | example domain |\n| 12 | 1.2.4.5 |' \
                                             ' resource_uri | 2023-03-14T14:28:20.110021 | 2023-03-20T11:38:26.279451 |'   \
                                             ' ip | example ip |\n| 11 | u | resource_uri | 2023-03-14T14:26:18.765256 |' \
                                             ' 2023-03-14T14:26:18.765256 | user-agent |  |\n'
    assert command_result.raw_response == mocked_response
    assert command_result.outputs == [{'created_ts': '2023-02-21T19:59:02.091404', 'id': 13,
                                       'modified_ts': '2023-02-21T19:59:02.091404', 'notes': 'example domain',
                                       'resource_uri': 'resource_uri', 'value': 'example.com', 'value_type': 'domain'},
                                      {'created_ts': '2023-03-14T14:28:20.110021', 'id': 12,
                                       'modified_ts': '2023-03-20T11:38:26.279451',
                                       'notes': 'example ip', 'resource_uri': 'resource_uri',
                                       'value': '1.2.4.5', 'value_type': 'ip'},
                                      {'created_ts': '2023-03-14T14:26:18.765256', 'id': 11,
                                       'modified_ts': '2023-03-14T14:26:18.765256',
                                       'notes': None, 'resource_uri': 'resource_uri', 'value': 'u', 'value_type': 'user-agent'}]


def test_list_import_job_command(mocker):
    """

    Given:
        -limit parameter

    When:
        - Call threatstream-list-import-job command

    Then:
        - Validate the command result

    """
    load_json = util_load_json('test_data/mocked_data.json')
    mocked_response = load_json.get('list_import_job_response')
    mocker.patch.object(Client, 'http_request', return_value=mocked_response)

    args: dict = {'limit': 2}
    client = mock_client()
    command_result = list_import_job_command(client, **args)
    assert command_result.readable_output == '### Import entries\n|Id|Date|Status|Submitted By|Intelligence Initiatives' \
                                             '|Included|Excluded|Tags|' \
                                             '\n|---|---|---|---|---|---|---|---|\n|' \
                                             ' 111111 | 2023-03-19T16:41:21.895297 | done | some_email | malware-intelligence |' \
                                             ' 0 | 0 |  |\n| 120759 | 2023-03-19T14:29:40.592787 | errors |' \
                                             ' some_email |  | 0 | 0 | tag1, tag2 |\n'
    assert command_result.raw_response == mocked_response
    assert command_result.outputs == load_json.get('list_import_job_output')


def test_list_rule_command(mocker):
    """

    Given:
        - limit parameter

    When:
        - Call threatstream-list-rule command

    Then:
        - Validate the command result

    """
    load_json = util_load_json('test_data/mocked_data.json')
    mocked_response = load_json.get('list_rule_response')
    mocker.patch.object(Client, 'http_request', return_value=mocked_response)

    args: dict = {'limit': 4}
    client = mock_client()
    command_result = list_rule_command(client, **args)
    assert command_result.readable_output == '### Rules\n|Name|Id|Matches|Created At|Modified At|Is Notify Me|Is Enabled|\n|' \
                                             '---|---|---|---|---|---|---|\n|' \
                                             ' some_name | 11111 | 0 | 2023-03-02T14:04:18.511057 |' \
                                             ' 2023-03-02T14:04:18.511057 | true | true |\n| name | 11112 | 0 |' \
                                             ' 2023-03-06T12:10:27.497296 |' \
                                             ' 2023-03-06T12:10:27.497296 | true | true |\n| name | 11111 | 0 |' \
                                             ' 2023-03-06T12:16:21.980678 |' \
                                             ' 2023-03-06T12:16:21.980678 | true | true |\n| name | 11113 | 0 |' \
                                             ' 2023-03-06T12:17:43.907629 |' \
                                             ' 2023-03-06T12:17:43.907629 | true | true |\n'
    assert command_result.raw_response == mocked_response
    assert command_result.outputs == load_json.get('list_rule_outputs')


def test_list_user_command(mocker):
    """

    Given:
        - limit parameter

    When:
        - Call threatstream-list-user command

    Then:
        - Validate the command result

    """
    load_json = util_load_json('test_data/mocked_data.json')
    mocked_response = load_json.get('list_user_response')
    mocker.patch.object(Client, 'http_request', return_value=mocked_response)

    args: dict = {'limit': 50}
    client = mock_client()
    command_result = list_user_command(client, **args)
    assert command_result.readable_output == '### Users\n|User Id|Email|Is Active|Last Login|\n|' \
                                             '---|---|---|---|\n| 111 | some_email | true | 2023-03-16T15:48:24.808760 ' \
                                             '|\n| 111 | some_email | true |  |\n| 111 | some_email |' \
                                             ' true | 2023-03-07T10:16:02.953700 |\n'
    assert command_result.raw_response == mocked_response
    assert command_result.outputs == load_json.get('list_user_outputs')


def test_list_investigation_command(mocker):
    """

    Given:
        - limit parameter

    When:
        - Call threatstream-list-investigation command

    Then:
        - Validate the command result

    """
    load_json = util_load_json('test_data/mocked_data.json')
    mocked_response = load_json.get('list_investigation_response')
    mocker.patch.object(Client, 'http_request', return_value=mocked_response)

    args: dict = {'limit': 2}
    client = mock_client()
    command_result = list_investigation_command(client, **args)
    assert command_result.readable_output == '### Investigations\n|Name|Id|Created At|Status|Source Type|Assignee|Reporter|\n|' \
                                             '---|---|---|---|---|---|---|\n| Test Incestigation | 111 |' \
                                             ' 2022-08-01T09:47:36.768535 |' \
                                             ' in-progress | user | some_email | some_email |\n| New | 111 |' \
                                             ' 2023-01-24T11:23:03.308344 | pending | rules | some_email | some_email |\n'
    assert command_result.raw_response == mocked_response
    assert command_result.outputs == load_json.get('list_investigation_output')


def test_create_rule_command(mocker):
    """

    Given:
        - rule_name, keywords, match_include parameters

    When:
        - Call threatstream-create-rule command

    Then:
        - Validate the command result

    """
    load_json = util_load_json('test_data/mocked_data.json')
    mocked_response = load_json.get('create_rule_response')
    mocker.patch.object(Client, 'http_request', return_value=mocked_response)

    args: dict = {'rule_name': "rule_1", "keywords": "keywords", "match_include": "observables"}
    client = mock_client()
    command_result = create_rule_command(client, **args)
    assert command_result.readable_output == 'The rule was created successfully with id: 11111.'
    assert command_result.raw_response == mocked_response


def test_update_rule_command(mocker):
    """

    Given:
        - rule_id, keywords, match_include, malware_ids parameters

    When:
        - Call threatstream-update-rule command

    Then:
        - Validate the command result

    """
    load_json = util_load_json('test_data/mocked_data.json')
    mocked_response = load_json.get('update_rule_response')
    mocker.patch.object(Client, 'http_request', return_value=mocked_response)

    args: dict = {'rule_id': "11111", "keywords": "keywords", "match_include": "sandbox", "malware_ids": 2222}
    client = mock_client()
    command_result = update_rule_command(client, **args)
    assert command_result.readable_output == '### Rules\n|Name|Id|Matches|Created At|Modified At|Is Notify Me|Is Enabled|\n|' \
                                             '---|---|---|---|---|---|---|\n| rule_1 | 11111 | 0 |' \
                                             ' 2023-03-21T11:55:54.411471 | 2023-03-21T12:29:37.984911 | true | true |\n'
    assert command_result.raw_response == mocked_response
    assert command_result.outputs == mocked_response


def test_delete_rule_command(mocker):
    """

    Given:
        - rule_id parameter

    When:
        - Call threatstream-delete-rule command

    Then:
        - Validate the command result

    """
    mocker.patch.object(Client, 'http_request', return_value=None)

    args: dict = {'rule_id': "11111"}
    client = mock_client()
    command_result = delete_rule_command(client, **args)
    assert command_result.readable_output == 'The rule was deleted successfully.'


def test_create_investigation_command(mocker):
    """

    Given:
        - name (Str): investigation name

    When:
        - Call threatstream-create-investigation command

    Then:
        - Validate the command result

    """
    load_json = util_load_json('test_data/mocked_data.json')
    mocked_response = load_json.get('create_investigation_response')
    mocker.patch.object(Client, 'http_request', return_value=mocked_response)

    args: dict = {'name': "new_investigation"}
    client = mock_client()
    command_result = create_investigation_command(client, **args)
    assert command_result.readable_output == 'Investigation was created successfully with ID: 111.\n'
    assert command_result.raw_response == mocked_response
    assert command_result.outputs == mocked_response


def test_update_investigation_command(mocker):
    """

    Given:
        - investigation_id, assignee_id, priority, status, tags, tlp arguments values

    When:
        - Call threatstream-update-investigation command

    Then:
        - Validate the command result

    """
    load_json = util_load_json('test_data/mocked_data.json')
    mocked_response = load_json.get('update_investigation_response')
    mocker.patch.object(Client, 'http_request', return_value=mocked_response)

    args: dict = {'investigation_id': '111', 'assignee_id': '111', 'priority': "Very Low",
                  'status': 'Pending', 'tags': 'tag1,tag2', 'tlp': 'Amber'}
    client = mock_client()
    command_result = update_investigation_command(client, **args)
    assert command_result.readable_output == 'Investigation was updated successfully with ID: 111'
    assert command_result.raw_response == mocked_response
    assert command_result.outputs == mocked_response


def test_delete_investigation_command(mocker):
    """

    Given:
        - investigation_id (Str): investigation id

    When:
        - Call threatstream-delete-investigation command

    Then:
        - Validate the command result

    """
    mocker.patch.object(Client, 'http_request', return_value=None)

    args: dict = {'investigation_id': "1111"}
    client = mock_client()
    command_result = delete_investigation_command(client, **args)
    assert command_result.readable_output == 'Investigation was deleted successfully.'


@pytest.mark.parametrize('args, get_from_jason, result_of_readable_output', [
    ({'investigation_id': '222', 'associated_actor_ids': '55555,11111'}, 'add_investigation_elements_all',
     'All The elements was added successfully to investigation ID: 222'),
    ({'investigation_id': '222', 'associated_actor_ids': '55555,22222'}, 'add_investigation_elements',
     'The following elements with IDs were successfully added: 55555. However, attempts to'
     ' add elements with IDs: 22222 were unsuccessful.')

])
def test_add_investigation_element_command(mocker, args, get_from_jason, result_of_readable_output):
    """

    Given:
        - investigation_id and associated_actor_ids arguments values

    When:
        - Call threatstream-add-investigation-element command

    Then:
        - Validate the command result

    """
    load_json = util_load_json('test_data/mocked_data.json')
    mocked_response = load_json.get(get_from_jason)
    mocker.patch.object(Client, 'http_request', return_value=mocked_response)

    client = mock_client()
    command_result = add_investigation_element_command(client, **args)
    assert command_result.readable_output == result_of_readable_output
    assert command_result.raw_response == mocked_response


def test_approve_import_job_command(mocker):
    """

    Given:
        - import_id (Str): import id

    When:
        - Call threatstream-approve-import-job command

    Then:
        - Validate the command result

    """
    load_json = util_load_json('test_data/mocked_data.json')
    mocked_response = load_json.get('approve_import_job_response')
    mocker.patch.object(Client, 'http_request', return_value=mocked_response)

    args: dict = {'import_id': '222222'}
    client = mock_client()
    command_result = approve_import_job_command(client, **args)
    assert command_result.readable_output == 'The import session was successfully approved.'
    assert command_result.raw_response == mocked_response


def test_search_threat_model_command(mocker):
    """

    Given:
        - model_type, signature_type, page, page_size

    When:
        - Call threatstream-search-threat-model command

    Then:
        - Validate the command result

    """
    load_json = util_load_json('test_data/mocked_data.json')
    mocked_response = load_json.get('search_threat_model_response')
    mocker.patch.object(Client, 'http_request', return_value=mocked_response)

    args: dict = {'model_type': "signature", 'signature_type': "Carbon Black Query,Bro,ClamAV", 'page': "2", 'page_size': "2"}
    client = mock_client()
    command_result = search_threat_model_command(client, **args)
    assert command_result.readable_output == '### Threat model entities\n|Id|Type|Name|Publication Status|Modified At|\n|' \
                                             '---|---|---|---|---|\n| 333 | signature | signature_threat_model_1 ' \
                                             '| new | 2023-03-19T10:09:09.150405+00:00 |\n| 444 | signature | test |' \
                                             ' published | 2022-10-08T05:18:20.389951+00:00 |\n'
    assert command_result.raw_response == mocked_response
    assert command_result.outputs == load_json.get('search_threat_model_outputs')


@pytest.mark.parametrize('mocker_return_value, expected_readable_output', [
    ({'ids': [2222, 3333], 'success': True}, 'The Attack Pattern entities with ids 2222, 3333'
                                             ' were associated successfully to entity id: 11111.'),
    ({'ids': [3333], 'success': True}, 'Part of the Attack Pattern entities with ids 3333 '
                                       'were associated successfully to entity id: 11111.'),

])
def test_add_threat_model_association_command(mocker, mocker_return_value, expected_readable_output):
    """

    Given:
        - name (Str): investigation name

    When:
        - Call threatstream-add-threat-model-association command

    Then:
        - Validate the command result

    """
    mocker.patch.object(Client, 'http_request', return_value=mocker_return_value)

    args: dict = {'entity_type': 'Actor', 'entity_id': '11111', 'associated_entity_ids': '2222,3333',
                  'associated_entity_type': 'Attack Pattern'}
    client = mock_client()
    command_result = add_threat_model_association_command(client, **args)
    assert command_result.readable_output == expected_readable_output
    assert command_result.raw_response == mocker_return_value


@pytest.mark.parametrize('model_type, publication_status, signature_type, message', [
    ('', '', 'bro, carbon black query', 'Unvalid values signature_type argument'),
    ('', 'pending_review, review requested,', '', 'Unvalid values publication_status argument'),
    ('ttl', '', '', 'Unvalid values model_type argument'),
])
def test_validate_values_search_threat_model(model_type, publication_status, signature_type, message):
    """

    Given:
        - model_type, publication_status, signature_type

    When:
        - Call validate_values_search_threat_model function

    Then:
        - Validate the error message

    """
    with pytest.raises(DemistoException) as de:
        validate_values_search_threat_model(model_type, publication_status, signature_type)

        assert (
            de.value.message == message
        )


@pytest.mark.parametrize('arguments_dict, expected_result', [
    ({'vulnerability': [1], 'actor': [2], 'intelligence2': [3], 'incident': [4],
      'signature': [5], 'tipreport': [6], 'ttp': [7], 'campaign': [8],
      'add_related_indicators': 1, 'is_update': False, 'investigation_id': 0},
     ([{'r_type': 'vulnerability', 'r_id': 1, 'add_related_indicators': 1},
      {'r_type': 'actor', 'r_id': 2, 'add_related_indicators': 1},
      {'r_type': 'intelligence2', 'r_id': 3, 'add_related_indicators': 1},
      {'r_type': 'incident', 'r_id': 4, 'add_related_indicators': 1},
      {'r_type': 'signature', 'r_id': 5, 'add_related_indicators': 1},
      {'r_type': 'tipreport', 'r_id': 6, 'add_related_indicators': 1},
      {'r_type': 'ttp', 'r_id': 7, 'add_related_indicators': 1},
      {'r_type': 'campaign', 'r_id': 8, 'add_related_indicators': 1}], [1, 2, 3, 4, 5, 6, 7, 8])),
    ({'vulnerability': [1], 'actor': [2], 'intelligence2': [3], 'incident': [4],
      'signature': [5], 'tipreport': [6], 'ttp': [7], 'campaign': [8],
      'add_related_indicators': 1, 'is_update': True, 'investigation_id': 111},
     ([{'r_type': 'vulnerability', 'r_id': 1, 'add_related_indicators': 1, 'investigation_id': 111},
      {'r_type': 'actor', 'r_id': 2, 'add_related_indicators': 1, 'investigation_id': 111},
      {'r_type': 'intelligence2', 'r_id': 3, 'add_related_indicators': 1, 'investigation_id': 111},
      {'r_type': 'incident', 'r_id': 4, 'add_related_indicators': 1, 'investigation_id': 111},
      {'r_type': 'signature', 'r_id': 5, 'add_related_indicators': 1, 'investigation_id': 111},
      {'r_type': 'tipreport', 'r_id': 6, 'add_related_indicators': 1, 'investigation_id': 111},
      {'r_type': 'ttp', 'r_id': 7, 'add_related_indicators': 1, 'investigation_id': 111},
      {'r_type': 'campaign', 'r_id': 8, 'add_related_indicators': 1, 'investigation_id': 111}], [1, 2, 3, 4, 5, 6, 7, 8])),
    ({'vulnerability': [], 'actor': [], 'intelligence2': [], 'incident': [],
      'signature': [], 'tipreport': [], 'ttp': [], 'campaign': [],
      'add_related_indicators': 1, 'is_update': True, 'investigation_id': 1111}, ([], [])),
])
def test_create_element_list(arguments_dict, expected_result):
    """

    Given:
        - arguments_dict (dict)

    When:
        - Call create_element_list function

    Then:
        - Validate the result

    """
    result = create_element_list(arguments_dict)
    assert result == expected_result


@pytest.mark.parametrize('investigation_action, new_investigation_name, existing_investigation_id, message', [
    ('Create New', None, None, "Please ensure to provide the 'new_investigation_name' argument when selecting the"
     " 'Create New' option for the 'investigation_action' argument."),
    ('Add To Existing', None, None, "Please ensure to provide the 'existing_investigation_id' argument when selecting"
     " the 'Add To Existing' option for the 'investigation_action' argument."),

])
def test_validate_investigation_action(investigation_action, new_investigation_name, existing_investigation_id, message):
    """

    Given:
        - investigation_action, new_investigation_name, existing_investigation_id

    When:
        - Call validate_investigation_action function

    Then:
        - Validate the error message

    """
    with pytest.raises(DemistoException) as de:
        validate_investigation_action(investigation_action, new_investigation_name, existing_investigation_id)

    assert de.value.message == message


@pytest.mark.parametrize('page, page_size, limit', [
    (2, 2, 0),
    (2, None, 2),
    (None, 2, 2)
])
def test_return_params_of_pagination_or_limit(page, page_size, limit):
    """

    Given:
        - page, page_size, limit

    When:
        - Call validate_investigation_action function

    Then:
        - Validate the error message

    """
    if page is None or page_size is None:
        with pytest.raises(DemistoException) as de:
            return_params_of_pagination_or_limit(page, page_size, limit)

        assert de.value.message == 'Please specify page and page_size'
    else:
        params = return_params_of_pagination_or_limit(page, page_size, limit)
        assert params == {'limit': 2, 'offset': 2}


@pytest.mark.parametrize('names_and_indicators_list, notes, expected_result', [
    ([('domain', ['some_domain']), ('email', ['some_email']),
      ('ip', ['some_ip']), ('md5', ['some_md5']),
      ('url', ['some_url']), ('user-agent', ['some_user_agent']),
      ('cidr', ['some_cidr'])], '',
     [{'value_type': 'domain', 'value': 'some_domain'},
      {'value_type': 'email', 'value': 'some_email'},
      {'value_type': 'ip', 'value': 'some_ip'},
      {'value_type': 'md5', 'value': 'some_md5'},
      {'value_type': 'url', 'value': 'some_url'},
      {'value_type': 'user-agent', 'value': 'some_user_agent'},
      {'value_type': 'cidr', 'value': 'some_cidr'}]),
    ([('domain', ['some_domain']), ('email', ['some_email']),
      ('ip', ['some_ip']), ('md5', ['some_md5']),
      ('url', ['some_url']), ('user-agent', ['some_user_agent']),
      ('cidr', ['some_cidr'])], 'some_note',
     [{'value_type': 'domain', 'value': 'some_domain', 'notes': 'some_note'},
      {'value_type': 'email', 'value': 'some_email', 'notes': 'some_note'},
      {'value_type': 'ip', 'value': 'some_ip', 'notes': 'some_note'},
      {'value_type': 'md5', 'value': 'some_md5', 'notes': 'some_note'},
      {'value_type': 'url', 'value': 'some_url', 'notes': 'some_note'},
      {'value_type': 'user-agent', 'value': 'some_user_agent', 'notes': 'some_note'},
      {'value_type': 'cidr', 'value': 'some_cidr', 'notes': 'some_note'}]),
])
def test_create_indicators_list(names_and_indicators_list, notes, expected_result):
    """

    Given:
        - names_and_indicators_list, notes

    When:
        - Call create_indicators_list function

    Then:
        - Validate the result

    """
    result = create_indicators_list(names_and_indicators_list, notes)
    assert result == expected_result


@pytest.mark.parametrize(
    "args, expected_data, expected_output",
    [
        (
            {"indicator_ids": "123,456", "tags": "tag1,tag2"},
            json.dumps({
                "ids": ["123", "456"],
                "tags": [{"name": "tag1", "tlp": "red"}, {"name": "tag2", "tlp": "red"}],
            }),
            "The tags have been successfully added for the following ids:\n `123, 456`",
        )
    ],
)
def test_add_indicator_tag_success(
    mocker, args: dict[str, str], expected_data: dict[str, str], expected_output: str
):
    """
    Given:
        - A list of indicator IDs and tags
    When:
        - `add_indicator_tag_command` is called with valid arguments
    Then:
        - A POST request should be made to add the tags
          and it should return a successful CommandResults
    """
    # Arrange
    client = mock_client()
    mock_http_request = mocker.patch.object(client, "http_request", return_value={})

    # Act
    result = add_indicator_tag_command(client, **args)

    # Assert
    assert expected_output == result.readable_output
    mock_http_request.assert_called_with(
        method="POST", url_suffix="v2/intelligence/bulk_tagging/", data=expected_data
    )


@pytest.mark.parametrize(
    "args, expected_output",
    [
        (
            {"indicator_ids": "1,2", "tags": "tag1,tag2"},
            "The tags were successfully deleted for the following ids:\n `1, 2`",
        )
    ],
)
def test_remove_indicator_tag_command_success(
    mocker, args: dict[str, str], expected_output: str
):
    """
    Given:
        - A list of indicator IDs and tags
    When:
        - `remove_indicator_tag_command` is called with valid arguments
    Then:
        - A PATCH request should be made to remove the tags
          and it should return a successful CommandResults
    """
    client = mock_client()
    # Mock API response
    mocker.patch.object(client, "remove_indicator_tag", json={})

    # Call function
    result = remove_indicator_tag_command(
        client=client,
        **args,
    )

    # Verify result
    assert result.readable_output == expected_output


@pytest.mark.parametrize(
    "without_credentials, expected_params",
    [
        (False, {'Authorization': 'apikey user:key'}),
        (True, {}),
    ],
)
def test_http_request_without_credentials(mocker, without_credentials: bool, expected_params: dict):
    """
    Given: Different boolean value for without_credentials argument of Client.http_request()
    When: Calling http_request()
    Then: Ensuring the credentials parameters are added if the value is True, and not added otherwise.
    """
    from AnomaliThreatStreamv3 import BaseClient
    http_request = mocker.patch.object(BaseClient, "_http_request", return_value={})
    client: BaseClient = mock_client()

    client.http_request("GET", "/hello", without_credentials=without_credentials)
    assert http_request.call_args.kwargs["headers"] == expected_params


def test_clone_ioc_command(mocker):
    """
    Given:
        - indicator id to clone
    When:
        - Call clone_ioc_command
    Then:
        - Validate the command result
    """

    # Mock API response
    mocked_response = {
        "import_session_id": "139",
        "job_id": "1b0ad011-e595-4f7f-8eb6"
    }

    readable_output = '### Clone operation results for indicator 123\n' \
                      '|Id|Import Session Id|Job Id|\n' \
                      '|---|---|---|\n' \
                      '| 123 | 139 | 1b0ad011-e595-4f7f-8eb6 |\n' \

    outputs = mocked_response
    outputs['ID'] = '123'

    client = mock_client()
    mocker.patch.object(Client, 'http_request', return_value=mocked_response)

    # Call function
    command_result = clone_ioc_command(
        client=client,
        indicator_id=123,
    )

    # Verify result
    assert command_result.raw_response == mocked_response
    assert command_result.readable_output == readable_output
    assert command_result.outputs == mocked_response


def test_edit_classification_job_command(mocker):
    """
    Given:
        - import  session id and JSON data of edits to be made
    When:
        - Call edit_classification_job_command
    Then:
        - Validate the command result
    """
    mocked_response = {'id': 123, "date": "2024-09-01T10:55:22.704146"}
    readable_output = 'The import session was successfully approved.'
    client = mock_client()
    mocker.patch.object(Client, 'http_request', return_value=mocked_response)

    # Call function
    command_result = edit_classification_job_command(
        client=client,
        import_id='139',
        data='{"is_public":false,"circles":[11111]}')

    # Verify result
    assert command_result.raw_response == mocked_response
    assert command_result.readable_output == readable_output
