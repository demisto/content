import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
from json.decoder import JSONDecodeError

import json
import traceback
import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

TOKEN = demisto.params().get('token')
# Remove trailing slash to prevent wrong URL path to service
SERVER = demisto.params()['url'][:-1] \
    if ('url' in demisto.params() and demisto.params()['url'].endswith('/')) else demisto.params().get('url')
# Should we use SSL
USE_SSL = not demisto.params().get('insecure', False)
# Headers to be sent in requests
HEADERS = {
    'Authorization': f'Token {TOKEN}',
    'Content-Type': 'application/json',
    'Accept': 'application/json'
}

ASSESSMENTS_TRANS = {
    'id': 'Id',
    'name': 'Name',
    'user': 'User',
    'users': 'Users',
    'owner': 'Owner',
    'groups': 'Groups',
    'creator': 'Creator',
    'created': 'Created',
    'end_date': 'EndDate',
    'modified': 'Modified',
    'start_date': 'StartDate',
    'description': 'Description',
    'project_state': 'ProjectState',
    'master_job_count': 'MasterJobCount',
    'default_schedule': 'DefaultSchedule',
    'default_asset_count': 'DefaultAssetCount',
    'project_template.id': 'ProjectTemplate.Id',
    'default_asset_group_count': 'DefaultAssetCount',
    'project_template.company': 'ProjectTemplate.Company',
    'project_template.created': 'ProjectTemplate.Created',
    'project_template.modified': 'ProjectTemplate.Modified',
    'project_template.template_name': 'ProjectTemplate.TemplateName',
    'project_template.default_schedule': 'ProjectTemplate.DefaultSchedule',
    'project_template.template_description': 'ProjectTemplate.TemplateDescription',
    'project_template.project_template_type.id': 'ProjectTemplate.ProjectTemplateType.Id',
    'project_template.project_template_type.name': 'ProjectTemplate.ProjectTemplateType.Name',
    'project_template.project_template_type.description': 'ProjectTemplate.ProjectTemplateType.Description',
}

TESTS_TRANS = {
    'id': 'Id',
    'name': 'Name',
    'description': 'Description',
    'project': 'Project',
    'total_asset_count': 'TotalAssetCount',
    'cron_expression': 'CronExpression',
    'runnable': 'Runnable',
    'last_result': 'LastResult',
    'scheduled_count': 'ScheduledCount',
    'user': 'User',
    'created': 'Created',
    'modified': 'Modified',
    'using_default_schedule': 'UsingDefaultSchedule',
    'using_default_assets': 'UsingDefaultAssets',
    'latest_instance_id': 'LatestInstanceId',
    'scenarios': {
        'name': 'Name',
        'id': 'Id'
    },
    'assets': {
        'id': 'Id',
        'ipv4_address': 'Ipv4Address',
        'hostname': 'Hostname',
        'product_name': 'ProductName',
        'modified': 'Modified',
        'status': 'Status'
    }
}

TEST_STATUS_TRANS = {
    'detected': 'Detected',
    'failed': 'Failed',
    'finished': 'Finished',
    'errored': 'Errored',
    'total': 'Total'
}

''' HELPER FUNCTIONS '''


def http_request(method, url_suffix, params=None, data=None):
    url = SERVER + url_suffix
    LOG(f'attackiq is attempting {method} request sent to {url} with params:\n{json.dumps(params, indent=4)}')
    res = requests.request(
        method,
        url,
        verify=USE_SSL,
        params=params,
        data=data,
        headers=HEADERS
    )
    # Handle error responses gracefully
    if res.status_code not in {200, 201}:
        error_reason = get_http_error_reason(res)
        return_error(f'Error in API call to AttackIQ [{res.status_code}] - {error_reason}')
    # TODO: Add graceful handling of various expected issues (Such as wrong URL and wrong creds)
    try:
        return res.json()
    except JSONDecodeError:
        return_error('Response contained no valid body. See logs for more information.',
                     error=f'attackiq response body:\n{res.content}')


def get_http_error_reason(res):
    """
    Get error reason from an AttackIQ http error
    Args:
        res: AttackIQ response

    Returns: Reason for http error
    """
    err_reason = res.reason
    try:
        res_json = res.json()
        if 'detail' in res_json:
            err_reason = f'{err_reason}. {res_json["detail"]}'
    except JSONDecodeError:
        pass
    return err_reason


def build_transformed_dict(src, trans_dict):
    """Builds a dictionary according to a conversion map

    Args:
        src (dict): original dictionary to build from
        trans_dict (dict): dict in the format { 'OldKey': 'NewKey', ...}

    Returns: src copy with changed keys
    """
    if isinstance(src, list):
        return [build_transformed_dict(x, trans_dict) for x in src]
    res = {}
    for key, val in trans_dict.items():
        if isinstance(val, dict):
            # handle nested list
            res[key.title()] = [build_transformed_dict(item, val) for item in demisto.get(src, key)]
        elif '.' in val:
            # handle nested vals
            res.update(create_nested_value(src, key, val))
        else:
            res[val] = demisto.get(src, key)
    return res


def create_nested_value(src_dict, from_key, to_key):
    res = {}
    sub_res = res
    to_key_lst = to_key.split('.')
    for sub_to_key in to_key_lst[:-1]:
        sub_res[sub_to_key] = {}
        sub_res = sub_res[sub_to_key]
    sub_res[to_key_lst[-1]] = demisto.get(src_dict, from_key)
    return res


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module():
    """
    Performs basic get request to get item samples
    """
    http_request('GET', '/v1/assessments')
    demisto.results('ok')


''' COMMANDS MANAGER / SWITCH PANEL '''


def activate_assessment_command():
    """ Implements attackiq-activate-assessment command
    """
    ass_id = demisto.getArg('assessment_id')
    raw_res = http_request('POST', f'/v1/assessments/{ass_id}/activate')
    hr = raw_res['message'] if 'message' in raw_res else f'Assessment {ass_id} activation was sent successfully.'
    demisto.results(hr)


def get_assessment_execution_status_command():
    """ Implements attackiq-get-assessment-execution-status command
    """
    ass_id = demisto.getArg('assessment_id')
    raw_res = http_request('GET', f'/v1/assessments/{ass_id}/is_on_demand_running')
    ex_status = raw_res.get('message')
    hr = f'Assessment {ass_id} execution is {"" if ex_status else "not "}finished.'
    ec = {
        'AttackIQ.Assessment(val.Id === obj.Id)': {
            'Finished': ex_status,
            'Id': ass_id
        }
    }
    return_outputs(hr, ec, raw_res)


def get_test_execution_status_command():
    """ Implements attackiq-get-test-execution-status command
    """
    test_id = demisto.getArg('test_id')
    raw_test_status = http_request('GET', f'/v1/tests/{test_id}/get_status')
    test_status = build_transformed_dict(raw_test_status, TEST_STATUS_TRANS)
    test_status['Id'] = test_id
    hr = tableToMarkdown(f'Test {test_id} status', test_status)
    return_outputs(hr, {'AttackIQ.Test(val.Id === obj.Id)': test_status}, raw_test_status)


def get_test_results_command():
    """ Implements attackiq-get-test-results command
    """
    pass


def list_assessments(assessment_id, page):
    if assessment_id:
        return http_request('GET', f'/v1/assessments/{assessment_id}')
    return http_request('GET', '/v1/assessments', params={'page': page})


def list_assessments_command():
    """ Implements attackiq-list-assessments command
    """
    args = demisto.args()
    assessment_id = args.get('assessment_id')
    page = args.get('page_number', '1')
    raw_assessments = list_assessments(assessment_id, page)
    if assessment_id:
        assessments_res = build_transformed_dict(raw_assessments, ASSESSMENTS_TRANS)
    else:
        assessments_res = build_transformed_dict(raw_assessments.get('results'), ASSESSMENTS_TRANS)
    hr = tableToMarkdown(f'AttackIQ Assessments Page #{page}', assessments_res)
    return_outputs(hr, {'AttackIQ.Assessment(val.Id === obj.Id)': assessments_res}, raw_assessments)


def list_tests_by_assessment_command():
    """ Implements attackiq-list-tests-by-assessment command
    """
    ass_id = demisto.getArg('assessment_id')
    raw_res = http_request('GET', f'/v1/tests', params={'project': ass_id})
    assessment_res = build_transformed_dict(raw_res.get('results'), TESTS_TRANS)
    ec = {'AttackIQ.Test(val.Id === obj.Id)': assessment_res}
    hr = tableToMarkdown(f'Assessment {ass_id} tests', assessment_res)
    return_outputs(hr, ec, raw_res)  # TODO: Improve hr


def run_all_tests_in_assessment_command():
    """ Implements attackiq-run-all-tests-in-assessment
    """
    pass


def main():
    handle_proxy()
    command = demisto.command()
    LOG(f'Command being called is {command}')
    try:
        if command == 'test-module':
            test_module()
        elif command == 'attackiq-activate-assessment':
            activate_assessment_command()
        elif command == 'attackiq-get-assessment-execution-status':
            get_assessment_execution_status_command()
        elif command == 'attackiq-get-test-execution-status':
            get_test_execution_status_command()
        elif command == 'attackiq-get-test-results':
            get_test_results_command()
        elif command == 'attackiq-list-assessments':
            list_assessments_command()
        elif command == 'attackiq-list-tests-by-assessment':
            list_tests_by_assessment_command()
        elif command == 'attackiq-run-all-tests-in-assessment':
            run_all_tests_in_assessment_command()
        else:
            return_error(f'Command {command} is not supported.')
    except Exception as e:
        message = f'Unexpected error: {str(e)}, traceback: {traceback.format_exc()}'
        return_error(message)


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
