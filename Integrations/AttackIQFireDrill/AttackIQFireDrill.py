import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
from requests import HTTPError
from typing import Dict, Any
from json.decoder import JSONDecodeError

import json
import traceback
import requests
import math

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

# Error messages
INVALID_ID_ERR_MSG = 'Error in API call. This may be happen if you provided an invalid id.'
API_ERR_MSG = 'Error in API call to AttackIQ. '
DEFAULT_PAGE_SIZE = 10

# Transformation dicts
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
    'project_state': 'AssessmentState',
    'master_job_count': 'MasterJobCount',
    'default_schedule': 'DefaultSchedule',
    'default_asset_count': 'DefaultAssetCount',
    'project_template.id': 'AssessmentTemplateId',
    'default_asset_group_count': 'DefaultAssetGroupCount',
    'project_template.company': 'AssessmentTemplateCompany',
    'project_template.created': 'AssessmentTemplateCreated',
    'project_template.modified': 'AssessmentTemplateModified',
    'project_template.template_name': 'AssessmentTemplateName',
    'project_template.default_schedule': 'AssessmentTemplateDefaultSchedule',
    'project_template.template_description': 'AssessmentTemplateDescription'
}

TESTS_TRANS = {
    'id': 'Id',
    'name': 'Name',
    'description': 'Description',
    'project': 'Assessment',
    'total_asset_count': 'TotalAssetCount',
    'cron_expression': 'CronExpression',
    'runnable': 'Runnable',
    'last_result': 'LastResult',
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
    'passed': 'Passed',
    'errored': 'Errored',
    'total': 'Total'
}

TEST_RESULT_TRANS = {
    'id': 'Id',
    'modified': 'Modified',
    'project.id': 'Assessment.Id',
    'project.name': 'Assessment.Name',
    'scenario.id': 'Scenario.Id',
    'scenario.name': 'Scenario.Name',
    'scenario.description': 'Scenario.Description',
    'asset.id': 'Asset.Id',
    'asset.ipv4_address': 'Asset.Ipv4Address',
    'asset.hostname': 'Asset.Hostname',
    'asset.product_name': 'Asset.ProductName',
    'asset.modified': 'Asset.Modified',
    'asset_group': 'Asset.AssetGroup',
    'job_state_name': 'JobState.Name',
    'outcome_name': 'Outcome.Name'
}

''' HELPER FUNCTIONS '''


def http_request(method, url_suffix, params=None, data=None):
    url = f'{SERVER}/{url_suffix}'
    LOG(f'attackiq is attempting {method} request sent to {url} with params:\n{json.dumps(params, indent=4)}')
    try:
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
            raise HTTPError(f'[{res.status_code}] - {error_reason}')
        try:
            return res.json()
        except JSONDecodeError:
            return_error('Response contained no valid body. See logs for more information.',
                         error=f'attackiq response body:\n{res.content}')
    except requests.exceptions.ConnectionError as e:
        LOG(str(e))
        return_error('Encountered issue reaching the endpoint, please check that you entered the URL correctly.')


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
    res: Dict[str, Any] = {}
    for key, val in trans_dict.items():
        if isinstance(val, dict):
            # handle nested list
            sub_res = res
            item_val = [build_transformed_dict(item, val) for item in (demisto.get(src, key) or [])]
            key = underscoreToCamelCase(key)
            for sub_key in key.split('.')[:-1]:
                if sub_key not in sub_res:
                    sub_res[sub_key] = {}
                sub_res = sub_res[sub_key]
            sub_res[key.split('.')[-1]] = item_val
        elif '.' in val:
            # handle nested vals
            update_nested_value(res, val, to_val=demisto.get(src, key))
        else:
            res[val] = demisto.get(src, key)
    return res


def create_invalid_id_err_msg(orig_err, error_codes):
    """
    Creates an 'invalid id' error message
    Args:
        orig_err (str): The original error message
        error_codes (list): List of error codes to look for

    Returns (str): Error message for invalid id
    """
    err_msg = API_ERR_MSG
    if any(err_code in orig_err for err_code in error_codes):
        err_msg += f'This may be happen if you provided an invalid id.\n'
    err_msg += orig_err
    return err_msg


def update_nested_value(src_dict, to_key, to_val):
    """
    Updates nested value according to transformation dict structure where 'a.b' key will create {'a': {'b': val}}
    Args:
        src_dict (dict): The original dict
        to_key (str): Key to transform to (expected to contain '.' to mark nested)
        to_val: The value that'll be put under the nested key
    """
    sub_res = src_dict
    to_key_lst = to_key.split('.')
    for sub_to_key in to_key_lst[:-1]:
        if sub_to_key not in sub_res:
            sub_res[sub_to_key] = {}
        sub_res = sub_res[sub_to_key]
    sub_res[to_key_lst[-1]] = to_val


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
    try:
        raw_res = http_request('POST', f'/v1/assessments/{ass_id}/activate')
        hr = raw_res['message'] if 'message' in raw_res else f'Assessment {ass_id} activation was sent successfully.'
        demisto.results(hr)
    except HTTPError as e:
        return_error(create_invalid_id_err_msg(str(e), ['403']))


def get_assessment_execution_status_command():
    """ Implements attackiq-get-assessment-execution-status command
    """
    ass_id = demisto.getArg('assessment_id')
    try:
        raw_res = http_request('GET', f'/v1/assessments/{ass_id}/is_on_demand_running')
        ex_status = raw_res.get('message')
        hr = f'Assessment {ass_id} execution is {"" if ex_status else "not "}running.'
        ec = {
            'AttackIQ.Assessment(val.Id === obj.Id)': {
                'Running': ex_status,
                'Id': ass_id
            }
        }
        return_outputs(hr, ec, raw_res)
    except HTTPError as e:
        return_error(create_invalid_id_err_msg(str(e), ['403']))


def get_test_execution_status_command():
    """ Implements attackiq-get-test-execution-status command
    """
    test_id = demisto.getArg('test_id')
    try:
        raw_test_status = http_request('GET', f'/v1/tests/{test_id}/get_status')
        test_status = build_transformed_dict(raw_test_status, TEST_STATUS_TRANS)
        test_status['Id'] = test_id
        hr = tableToMarkdown(f'Test {test_id} status', test_status)
        return_outputs(hr, {'AttackIQTest(val.Id === obj.Id)': test_status}, raw_test_status)
    except HTTPError as e:
        return_error(create_invalid_id_err_msg(str(e), ['500']))


def build_test_results_hr(test_results, test_id):
    """
    Creates test results human readable
    Args:
        test_results (list): Results of the test (after being transformed)
        test_id (str): ID of the test

    Returns: Human readable of test results
    """
    keys = ['Assessment Name', 'Scenario Name', 'Hostname', 'Asset IP', 'Job State', 'Modified', 'Outcome']
    test_results_mod = []
    for t_res in test_results:
        assessment = t_res.get('Assessment')
        asset = t_res.get('Asset')
        scenario = t_res.get('Scenario')
        hr_items = {
            keys[0]: assessment.get('Name'),
            keys[1]: scenario.get('Name'),
            keys[2]: asset.get('Hostname'),
            keys[3]: asset.get('Ipv4Address'),
            keys[4]: demisto.get(t_res, 'JobState.Name'),
            keys[5]: t_res.get('Modified'),
            keys[6]: demisto.get(t_res, 'Outcome.Name')
        }
        test_results_mod.append(hr_items)
    return tableToMarkdown(f'Test Results for {test_id}', test_results_mod, keys)


def get_page_number_and_page_size(args):
    """
    Get arguments page_number and page_size from args
    Args:
        args (dict): Argument dictionary, with possible page_number and page_size keys

    Returns (int, int): Return a tuple of (page_number, page_size)

    """
    page = args.get('page_number', 1)
    try:
        page = int(page)
    except (ValueError, TypeError):
        return_error(f'Error: Invalid page_number value. {page} Is not valid. Please enter a positive integer.')
    try:
        page_size = int(args.get('page_size', DEFAULT_PAGE_SIZE))
    except (ValueError, TypeError):
        page_size = DEFAULT_PAGE_SIZE
    return page, page_size


'''  Commands  '''


def get_test_results_command(args=demisto.args()):
    """ Implements attackiq-get-test-results command
    """
    test_id = args.get('test_id')
    params = {
        'page': args.get('page', '1'),
        'test_id': test_id,
        'show_last_result': args.get('show_last_result') == 'True'
    }
    try:
        raw_test_res = http_request('GET', '/v1/results', params=params)
        test_res = build_transformed_dict(raw_test_res['results'], TEST_RESULT_TRANS)
        hr = build_test_results_hr(test_res, test_id)
        return_outputs(hr, {'AttackIQTestResult(val.Id === obj.Id)': test_res}, raw_test_res)
    except HTTPError as e:
        return_error(create_invalid_id_err_msg(str(e), ['500']))


def get_assessments(page='1', assessment_id=None, page_size=DEFAULT_PAGE_SIZE):
    """
    Fetches assessments from attackIQ
    Args:
        page (str or int): Page number to fetch
        assessment_id (str): (Optional) If provided will fetch only the assessment with matching ID

    Returns: Assessments from attackIQ
    """
    params = {
        'page_size': page_size,
        'page': page
    }
    if assessment_id:
        return http_request('GET', f'/v1/assessments/{assessment_id}')
    return http_request('GET', '/v1/assessments', params=params)


def list_assessments_command():
    """ Implements attackiq-list-assessments command
    """
    page, page_size = get_page_number_and_page_size(demisto.args())
    raw_assessments = get_assessments(page=page, page_size=page_size)
    assessments_res = build_transformed_dict(raw_assessments.get('results'), ASSESSMENTS_TRANS)
    ass_cnt = raw_assessments.get('count')
    total_pages = math.ceil(ass_cnt / page_size)
    remaining_pages = total_pages - page
    context = {
        'AttackIQ.Assessment(val.Id === obj.Id)': assessments_res,
        'AttackIQ.Assessment(val.Count).Count': ass_cnt,
        'AttackIQ.Assessment(val.RemainingPages).RemainingPages': remaining_pages
    }
    hr = tableToMarkdown(f'AttackIQ Assessments Page {page}/{total_pages}', assessments_res,
                         headers=['Id', 'Name', 'Description', 'User', 'Created', 'Modified'])
    return_outputs(hr, context, raw_assessments)


def get_assessment_by_id_command():
    """ Implements attackiq-get-assessment-by-id command
        """
    assessment_id = demisto.getArg('assessment_id')
    try:
        raw_assessments = get_assessments(assessment_id=assessment_id)
        assessments_res = build_transformed_dict(raw_assessments, ASSESSMENTS_TRANS)
        hr = tableToMarkdown(f'AttackIQ Assessment {assessment_id}', assessments_res,
                             headers=['Id', 'Name', 'Description', 'User', 'Created', 'Modified'])
        return_outputs(hr, {'AttackIQ.Assessment(val.Id === obj.Id)': assessments_res}, raw_assessments)
    except HTTPError as e:
        return_error(create_invalid_id_err_msg(str(e), ['403']))


def build_tests_hr(assessment_res):
    """
    Creates tests human readable
    Args:
        assessment_res (list): Assignment ID

    Returns: Human readable string (md format) of tests
    """
    hr = ''
    for ass in assessment_res:
        ass_cpy = dict(ass)
        assets = ass_cpy.pop('Assets', {})
        scenarios = ass_cpy.pop('Scenarios', {})
        test_name = ass_cpy.get('Name')
        hr += tableToMarkdown(f'Test - {test_name}', ass_cpy,
                              headers=['Id', 'Name', 'Created', 'Modified', 'Runnable', 'LastResult'],
                              headerTransform=pascalToSpace)
        hr += tableToMarkdown(f'Assets ({test_name})', assets)
        hr += tableToMarkdown(f'Scenarios ({test_name})', scenarios)
    return hr


def list_tests_by_assessment_command():
    """ Implements attackiq-list-tests-by-assessment command
    """
    page, page_size = get_page_number_and_page_size(demisto.args())
    ass_id = demisto.getArg('assessment_id')
    raw_res = http_request('GET', f'/v1/tests', params={'project': ass_id})
    test_cnt = raw_res.get('count')
    tests_res = build_transformed_dict(raw_res.get('results'), TESTS_TRANS)
    total_pages = math.ceil(test_cnt / page_size)
    remaining_pages = total_pages - page
    context = {
        'AttackIQTest(val.Id === obj.Id)': tests_res,
        'AttackIQTest(val.Count).Count': test_cnt,
        'AttackIQTest(val.RemainingPages).RemainingPages': remaining_pages
    }
    hr = build_tests_hr(tests_res)
    return_outputs(hr, context, raw_res)


def run_all_tests_in_assessment_command():
    """ Implements attackiq-run-all-tests-in-assessment command
    """
    args = demisto.args()
    ass_id = args.get('assessment_id')
    try:
        raw_res = http_request('POST', f'/v1/assessments/{ass_id}/run_all_tests')
        hr = raw_res['message'] if 'message' in raw_res else \
            f'Request to run all tests for assessment {ass_id} was sent successfully.'
        demisto.results(hr)
    except HTTPError as e:
        return_error(create_invalid_id_err_msg(str(e), ['403']))


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
        elif command == 'attackiq-get-assessment-by-id':
            get_assessment_by_id_command()
        elif command == 'attackiq-list-tests-by-assessment':
            list_tests_by_assessment_command()
        elif command == 'attackiq-run-all-tests-in-assessment':
            run_all_tests_in_assessment_command()
        else:
            return_error(f'Command {command} is not supported.')
    except HTTPError as e:
        # e is expected to contain parsed error message
        err = f'{API_ERR_MSG}{str(e)}'
        return_error(err)
    except Exception as e:
        message = f'Unexpected error: {str(e)}, traceback: {traceback.format_exc()}'
        return_error(message)


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
