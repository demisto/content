import emoji

import demistomock as demisto
from tempfile import mkdtemp
from AnomaliThreatStreamv3 import main, get_indicators, \
    REPUTATION_COMMANDS, Client, DEFAULT_INDICATOR_MAPPING, \
    FILE_INDICATOR_MAPPING, INDICATOR_EXTENDED_MAPPING, get_model_description, import_ioc_with_approval, \
    import_ioc_without_approval, create_model, update_model, submit_report, add_tag_to_model, file_name_to_valid_string
from CommonServerPython import *
import pytest


def util_load_json(path):
    with open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def util_tmp_json_file():
    tmp_dir = mkdtemp()
    file_name = 'test_file.txt'
    file_obj = {
        'name': file_name,
        'path': os.path.join(tmp_dir, file_name)
    }
    with open(file_obj['path'], 'w') as f:
        json.dump(MOCK_OBJECTS, f)

    return file_obj


def mock_client():
    return Client(
        base_url='',
        user_name='',
        api_key='',
        proxy=False,
        should_create_relationships=True,
        verify=False,
        reliability='B - Usually reliable'
    )


MOCK_OBJECTS = {"objects": [{"srcip": "8.8.8.8", "itype": "mal_ip", "confidence": 50},
                            {"srcip": "1.1.1.1", "itype": "apt_ip"}]}

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
        mocker.patch.object(Client, 'http_request', return_value=mocked_ioc_result)
        mocker.patch.object(demisto, 'args', return_value={value_key: ioc_value, 'status': 'active'})
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

        test_indicator = dict(confidence=confidence, value='test_ioc', asn='', meta=dict(registrant_name='test'))
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

        test_indicator = dict(confidence=55,
                              value='test_ioc',
                              asn='test_asn',
                              org='test_org',
                              tlp='test_tlp',
                              country='test_country',
                              meta=dict(registrant_name='test', maltype='test_maltype'))
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

        for ioc in ['ip', 'domain', 'file', 'url']:
            mocker.patch.object(demisto, 'command', return_value=ioc)
            mocker.patch.object(demisto, 'args', return_value={ioc: 'test_ioc'})

            # run
            main()

        # validate
        mocked_search.call_args[0][1]['status'] == exp_status_param

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
        test_indicator = dict(value='test_ioc', asn='', meta=dict(registrant_name='test'))
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
        mocked_file_path = util_tmp_json_file()
        mocker.patch.object(demisto, 'getFilePath', return_value=mocked_file_path)
        mocker.patch.object(Client, 'http_request', return_value={'success': True, 'import_session_id': 'test_session_id'})

        # run
        result = import_ioc_with_approval(mock_client(), import_type, 'test_value')

        # validate

        files = Client.http_request.call_args[1]['files']
        data = Client.http_request.call_args[1]['data']

        if files:  # in case of import_type=file-id
            assert files['file'][0] == 'test_file.txt'
        else:
            assert data[import_type] == 'test_value'

        assert all(key in data for key in ['classification', 'confidence', 'threat_type', 'severity'])

        assert result.outputs == 'test_session_id'

    def test_import_indicator_without_approval__happy_path(self, mocker):
        """
        Given:
            - Indicator to import without approval

        When:
            - Call the import without approval command

        Then:
            - Validate the request and response are as expected
        """

        # prepare
        mocked_file_path = util_tmp_json_file()
        mocker.patch.object(demisto, 'getFilePath', return_value=mocked_file_path)
        mocker.patch.object(Client, 'http_request')

        # run
        result = import_ioc_without_approval(
            mock_client(),
            file_id='test_file_id',
            classification='Private',
            confidence=50,
            severity='low',
            allow_unresolved=True,
        )

        # validate
        json_data = Client.http_request.call_args[1]['json']['meta']
        assert all(key in json_data for key in ['classification', 'confidence', 'severity', 'allow_unresolved'])
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
        ('threatstream-get-analysis-status', dict(report_id=1), ['ReportID', 'Status', 'Platform', 'Verdict']),
        ('threatstream-get-passive-dns', dict(value='test'), ['Domain', 'Rrtype', 'Source', 'FirstSeen']),
        ('threatstream-get-model-list', dict(model='Actor'), ['Name', 'ID', 'CreatedTime', 'Type']),
        ('threatstream-get-model-description', dict(model='Actor', id='test'), ['File', 'FileID']),
        ('threatstream-get-indicators-by-model', dict(model='Actor', id=1), ['ModelType', 'ModelID', 'Indicators']),
        ('threatstream-get-indicators', {}, INDICATOR_EXTENDED_MAPPING.keys()),
        ('threatstream-supported-platforms', {}, ['Platform', 'Name', 'Types', 'Label']),
        ('threatstream-analysis-report', dict(report_id=1), ['Category', 'Started', 'ReportID', 'Verdict', 'Network'])
    ]

    commands_with_expected_output = [
        ('threatstream-get-analysis-status', dict(report_id=1), 'No report found with id 1'),
        ('threatstream-get-passive-dns', dict(value='test_val'), 'No Passive DNS enrichment data found for test_val'),
        ('threatstream-get-model-list', dict(model='Actor'), 'No Threat Model Actor found.'),
        ('threatstream-get-model-description', dict(model='Actor', id=1),
         'No description found for Threat Model Actor with id 1'),
        ('threatstream-get-indicators-by-model', dict(model='Actor', id=1),
         'No indicators found for Threat Model Actor with id 1'),
        ('threatstream-get-indicators', {}, 'No indicators found from ThreatStream'),
        ('threatstream-supported-platforms', {}, 'No supported platforms found for default sandbox'),
        ('threatstream-analysis-report', dict(report_id=1), 'No report found with id 1')
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
        assert all(key in context.keys() for key in expected_context_keys)

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
            ('threatstream-get-model-list', dict(model='Actor'),
             dict(limit='50', skip_intelligence="true", skip_associations="true")),
            ('threatstream-get-model-description', dict(model='Actor', id=1),
             dict(skip_intelligence="true", skip_associations="true")),
            ('threatstream-get-indicators-by-model', dict(model='Actor', id=1), dict(limit='20')),
            ('threatstream-get-indicators', {}, dict(limit=20, offset=0)),
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
            ('signature', dict(notes='test_description')),
            ('tipreport', dict(body='test_description')),
            ('actor', dict(description='test_description'))
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
        mocked_result.call_args[0][1] == 'test_description'.encode(encoding='UTF-8')


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
        mocked_report = dict(success=True, reports=dict(test_platform=dict(id='report_id')))
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
        file_obj = util_tmp_json_file()
        mocker.patch.object(demisto, 'getFilePath', return_value=file_obj)
        mocked_report = dict(success=True, reports=dict(test_platform=dict(id='report_id')))
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
        mocked_report = dict(success=True, reports=dict(test_platform=dict(id='report_id')))
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
        mocker.patch.object(Client, 'http_request', return_value=dict(success=True))

        # run
        res = add_tag_to_model(mock_client(), model_id='test_actor_id', model='Actor', tags='tag_1,tag_2')

        # validate
        data = json.loads(Client.http_request.call_args[1]['data'])

        assert data['tags'][1] == dict(name='tag_2', tlp='red')
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
        mocker.patch.object(Client, 'http_request', return_value=dict(success=False))

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
            {'objects': INDICATOR * 1000},
            {'objects': INDICATOR * 1000},
            {'objects': INDICATOR * 1000},
            {'objects': INDICATOR * 1000},
            {'objects': INDICATOR * 1000},
            {'objects': INDICATOR * 1000},
            {'objects': INDICATOR * 1000},
        ])
        client = Client(
            base_url='',
            user_name='',
            api_key='',
            verify=False,
            proxy=False,
            reliability='B - Usually reliable',
            should_create_relationships=False,
        )

        results = get_indicators(client, limit='7000')

        assert len(results.outputs) == 7000
