import demistomock as demisto
from Anomali_ThreatStream_v2 import main


def http_request_mock(req_type, suffix, params, data, files):
    return {
        'success': True,
        'import_session_id': params,
        'data': data,
    }


def return_outputs_mock(params=[], data=[], filler=''):
    return {
        'params': params,
        'data': data
    }


def main_mock():
    ''' COMMANDS MANAGER / SWITCH PANEL '''

    try:
        handle_proxy()
        args = prepare_args(demisto.args())
        if demisto.command() == 'test-module':
            test_module()
        elif demisto.command() == 'ip':
            ips_reputation_command(**args)
        elif demisto.command() == 'domain':
            domains_reputation_command(**args)
        elif demisto.command() == 'file':
            files_reputation_command(**args)
        elif demisto.command() == 'url':
            urls_reputation_command(**args)
        elif demisto.command() == 'threatstream-email-reputation':
            get_email_reputation(**args)
        elif demisto.command() == 'threatstream-get-passive-dns':
            get_passive_dns(**args)
        elif demisto.command() == 'threatstream-import-indicator-with-approval':
            return import_ioc_with_approval(**args)
        elif demisto.command() == 'threatstream-get-model-list':
            get_model_list(**args)
        elif demisto.command() == 'threatstream-get-model-description':
            get_model_description(**args)
        elif demisto.command() == 'threatstream-get-indicators-by-model':
            get_iocs_by_model(**args)
        elif demisto.command() == 'threatstream-create-model':
            create_model(**args)
        elif demisto.command() == 'threatstream-update-model':
            update_model(**args)
        elif demisto.command() == 'threatstream-submit-to-sandbox':
            submit_report(**args)
        elif demisto.command() == 'threatstream-get-analysis-status':
            get_submission_status(**args)
        elif demisto.command() == 'threatstream-analysis-report':
            get_report(**args)
        elif demisto.command() == 'threatstream-supported-platforms':
            supported_platforms(**args)
        elif demisto.command() == 'threatstream-get-indicators':
            get_indicators(**args)
        elif demisto.command() == 'threatstream-add-tag-to-model':
            add_tag_to_model(**args)

    except Exception as e:
        if isinstance(e, MissingSchema):
            return_error("Not valid server url. Check url format")
        elif isinstance(e, ConnectionError):
            return_error("The server is not reachable.")
        else:
            return_error(e)


package_500_error = {
    'import_type': 'url',
    'import_value': 'www.demisto.com',
    'ip_mapping': 'yes',
    'md5_mapping': 'no'
}


def test_ioc_approval_500_error(mocker):
    mocker.patch('Anomali_ThreatStream_v2.main', side_effect=main_mock)
    mocker.patch('Anomali_ThreatStream_v2.http_request', side_effect=http_request_mock)
    mocker.patch('CommonServerPython.return_outputs', side_effect=return_outputs_mock)
    mocker.patch.object(demisto, 'args', return_value=package_500_error)
    mocker.patch.object(demisto, 'command', return_value='threatstream-import-indicator-with-approval')
    mocker.patch.object(demisto, 'results')

    results = main()

    assert results == []
