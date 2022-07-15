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
SERVER = demisto.params().get('url')[:-1] \
    if ('url' in demisto.params() and demisto.params()['url'].endswith('/')) else demisto.params().get('url', '')
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
    'project_id': 'Assessment.Id',
    'project_name': 'Assessment.Name',
    'scenario.id': 'Scenario.Id',
    'scenario.name': 'Scenario.Name',
    'scenario.description': 'Scenario.Description',
    'asset.id': 'Asset.Id',
    'asset.ipv4_address': 'Asset.Ipv4Address',
    'asset.hostname': 'Asset.Hostname',
    'asset.product_name': 'Asset.ProductName',
    'asset.modified': 'Asset.Modified',
    'asset_group': 'Asset.AssetGroup',
    'job_state_name': 'JobState',
    'outcome_name': 'Outcome'
}

''' HELPER FUNCTIONS '''


def http_request(method, url_suffix, params=None, data=None):
    url = urljoin(SERVER, url_suffix)
    LOG(f'AttackIQ is attempting {method} request sent to {url} with params:\n{json.dumps(params, indent=4)} \n '
        f'data:\n"{json.dumps(data)}')
    try:
        res = requests.request(
            method,
            url,
            verify=USE_SSL,
            params=params,
            data=data,
            headers=HEADERS
        )
        if res.status_code == 204:
            return ''
        # Handle error responses gracefully
        if res.status_code not in {200, 201}:
            error_reason = get_http_error_reason(res)
            raise HTTPError(f'[{res.status_code}] - {error_reason}')
        try:
            return res.json()
        except JSONDecodeError:
            return_error('Response contained no valid body. See logs for more information.',
                         error=f'AttackIQ response body:\n{res.content!r}')
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
        err_msg += 'This may be happen if you provided an invalid id.\n'
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


def get_page_number_and_page_size(args):
    """
    Get arguments page_number and page_size from args
    Args:
        args (dict): Argument dictionary, with possible page_number and page_size keys

    Returns (int, int): Return a tuple of (page_number, page_size)

    """
    page = args.get('page_number', 1)
    page_size = args.get('page_size', DEFAULT_PAGE_SIZE)
    err_msg_format = 'Error: Invalid {arg} value. "{val}" Is not a valid value. Please enter a positive integer.'
    try:
        page = int(page)
        if page <= 0:
            raise ValueError()
    except (ValueError, TypeError):
        return_error(err_msg_format.format(arg='page_number', val=page))
    try:
        page_size = int(page_size)
        if page_size <= 0:
            raise ValueError()
    except (ValueError, TypeError):
        return_error(err_msg_format.format(arg='page_size', val=page_size))
    return page, page_size


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


def build_test_results_hr(test_results, test_id, page, tot_pages):
    """
    Creates test results human readable
    Args:
        page (int): Current page
        tot_pages (int): Total pages
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
            keys[4]: demisto.get(t_res, 'JobState'),
            keys[5]: t_res.get('Modified'),
            keys[6]: demisto.get(t_res, 'Outcome.Name')
        }
        test_results_mod.append(hr_items)
    return tableToMarkdown(f'Test Results for {test_id}\n ### Page {page}/{tot_pages}', test_results_mod, keys)


def get_test_results(page, page_size, test_id, show_last_res):
    """
    Get test results response
    Args:
        page (int): Page number
        page_size (int): Page size
        test_id (int): ID of test
        show_last_res (bool): Flag for showing only last result

    Returns: Test results
    """
    params = {
        'page': page,
        'page_size': page_size,
        'test_id': test_id,
        'show_last_result': show_last_res
    }
    return http_request('GET', '/v1/results', params=params)


def get_test_results_command(args=demisto.args()):
    """ Implements attackiq-get-test-results command
    """
    test_id = args.get('test_id')
    outcome_filter = args.get('outcome_filter')
    page, page_size = get_page_number_and_page_size(demisto.args())
    try:
        raw_test_res = get_test_results(page, page_size, test_id, args.get('show_last_result') == 'True')
        test_cnt = raw_test_res.get('count')
        if test_cnt == 0:
            return_outputs('No results were found', {})
        else:
            total_pages = math.ceil(test_cnt / page_size)
            remaining_pages = total_pages - page
            if remaining_pages < 0:
                remaining_pages = 0
            test_res = build_transformed_dict(raw_test_res['results'], TEST_RESULT_TRANS)
            if outcome_filter:
                test_res = list(filter(lambda x: x.get('Outcome') == outcome_filter, test_res))
            context = {
                'AttackIQTestResult(val.Id === obj.Id)': test_res,
                'AttackIQTestResult(val.Count).Count': test_cnt,
                'AttackIQTestResult(val.RemainingPages).RemainingPages': remaining_pages
            }
            hr = build_test_results_hr(test_res, test_id, page, total_pages)
            return_outputs(hr, context, raw_test_res)
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
    if remaining_pages < 0:
        remaining_pages = 0
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


def build_tests_hr(tests_res, ass_id, page_num, tot_pages):
    """
    Creates tests human readable
    Args:
        tot_pages (int): Total pages
        page_num (int): Current page
        ass_id (str): Assignment ID
        tests_res (list): Transformed result of test

    Returns: Human readable string (md format) of tests
    """
    hr = f'# Assessment {ass_id} tests\n## Page {page_num} / {tot_pages}\n'
    for test in tests_res:
        test = dict(test)
        assets = test.pop('Assets', {})
        scenarios = test.pop('Scenarios', {})
        test_name = test.get('Name')
        hr += tableToMarkdown(f'Test - {test_name}', test,
                              headers=['Id', 'Name', 'Created', 'Modified', 'Runnable', 'LastResult'],
                              headerTransform=pascalToSpace)
        hr += tableToMarkdown(f'Assets ({test_name})', assets)
        hr += tableToMarkdown(f'Scenarios ({test_name})', scenarios)
    if not hr:
        hr = 'Found no tests'
    return hr


def list_tests_by_assessment(params):
    return http_request('GET', '/v1/tests', params=params)


def list_tests_by_assessment_command():
    """ Implements attackiq-list-tests-by-assessment command
    """
    page, page_size = get_page_number_and_page_size(demisto.args())
    ass_id = demisto.getArg('assessment_id')
    params = {
        'project': ass_id,
        'page_size': page_size,
        'page': page
    }
    raw_res = list_tests_by_assessment(params)
    test_cnt = raw_res.get('count')
    if test_cnt == 0:
        return_outputs('No results were found', {})
    else:
        tests_res = build_transformed_dict(raw_res.get('results'), TESTS_TRANS)
        total_pages = math.ceil(test_cnt / page_size)
        remaining_pages = total_pages - page
        if remaining_pages < 0:
            remaining_pages = 0
        context = {
            'AttackIQTest(val.Id === obj.Id)': tests_res,
            'AttackIQTest(val.Count).Count': test_cnt,
            'AttackIQTest(val.RemainingPages).RemainingPages': remaining_pages
        }
        hr = build_tests_hr(tests_res, ass_id, page, total_pages)
        return_outputs(hr, context, raw_res)


def run_all_tests_in_assessment_command():
    """ Implements attackiq-run-all-tests-in-assessment command
    """
    args = demisto.args()
    ass_id = args.get('assessment_id')
    on_demand_only = args.get('on_demand_only')
    try:
        params = {'on_demand_only': on_demand_only == 'True'}
        raw_res = http_request('POST', f'/v1/assessments/{ass_id}/run_all_tests', params=params)
        hr = raw_res['message'] if 'message' in raw_res else \
            f'Request to run all tests for assessment {ass_id} was sent successfully.'
        demisto.results(hr)
    except HTTPError as e:
        return_error(create_invalid_id_err_msg(str(e), ['403']))


@logger
def list_templates_command():
    """
    Returns:
        A list of all assesment templates.
    """

    res = http_request('GET', '/v1/project_template_types')
    templates = []
    for template_group in res.get("results", []):
        for template in template_group.get('project_templates', []):
            template_dict = {
                "ID": template.get("id"),
                'Name': template.get("template_name"),
                'Description': template.get("template_description"),
                'ProjectName': template.get('project_name'),
                'ProjectDescription': template.get('project_description'),
                'Hidden': template.get('hidden')
            }
            templates.append(template_dict)
    ec = {
        "AttackIQ.Template(val.ID && val.ID === obj.ID)": templates
    }
    hr = tableToMarkdown("Templates:", templates, ["ID", "Name", 'Description', 'ProjectName', 'ProjectDescription'])
    return_outputs(hr, ec, res)


@logger
def list_assets_command():
    """

    Returns:
        A list of all configured assets.
    """
    res = http_request('GET', '/v1/assets')
    assets = []
    for asset in res.get('results', []):
        asset_dict = {
            'ID': asset.get('id', ''),
            'Description': asset.get('description', ''),
            'IPv4': asset.get('ipv4_address', ''),
            'IPv6': asset.get('ipv6_address', ''),
            'MacAddress': asset.get('mac_address', ''),
            'ProcessorArch': asset.get('processor_arch', ''),
            'ProductName': asset.get('product_name', ''),
            'Hostname': asset.get('hostname', ''),
            'Domain': asset.get('domain_name', ''),
            'User': asset.get('user', ''),
            'Status': asset.get('status', '')
        }
        groups = []
        for group in asset.get('asset_groups', []):
            temp_group = {
                "ID": group.get('id'),
                "Name": group.get('name')
            }
            groups.append(temp_group)
        asset_dict['Groups'] = groups
        assets.append(asset_dict)
    ec = {
        "AttackIQ.Asset(val.ID && val.ID === obj.ID)": assets
    }
    hr = tableToMarkdown("Assets:", assets, ['ID', 'Hostname', 'IPv4', 'MacAddress', 'Domain',
                                             'Description', 'User', 'Status'])

    return_outputs(hr, ec, res)


@logger
def create_assessment_command():
    """
    name - The name of the assesment to create.

    Returns:

    """
    body = {
        "project_name": demisto.args().get('name'),
        "template": demisto.args().get('template_id')
    }

    try:
        res = http_request('POST', '/v1/assessments/project_from_template', data=json.dumps(body))
    except Exception as e:
        raise ValueError(f"Could not create an assessment. Specifically: {str(e)}")

    assessment_id = res.get('project_id')
    raw_assessments = get_assessments(assessment_id=assessment_id)
    assessments_res = build_transformed_dict(raw_assessments, ASSESSMENTS_TRANS)
    hr = tableToMarkdown(f'Created Assessment: {assessment_id} successfully.', assessments_res,
                         headers=['Id', 'Name', 'Description', 'User', 'Created', 'Modified'])
    return_outputs(hr, {'AttackIQ.Assessment(val.Id === obj.Id)': assessments_res}, raw_assessments)


@logger
def add_assets_to_assessment():
    assessment_id = demisto.args().get('assessment_id')
    assets = demisto.args().get('assets')
    asset_groups = demisto.args().get('asset_groups')

    data = {}
    if assets:
        data['assets'] = assets
    if asset_groups:
        data['asset_groups'] = asset_groups

    if data == {}:
        raise ValueError("No asset or asset groups were specified.")
    try:
        res = http_request('POST', f'/v1/assessments/{assessment_id}/update_defaults', data=json.dumps(data))
        demisto.results(res.get('message', ''))
    except Exception as e:
        if '403' in str(e):
            raise ValueError("Could not find either the assessment or one of the assets/asset groups.")
        else:
            raise


@logger
def delete_assessment_command():
    assessment_id = demisto.args().get('assessment_id')
    try:
        http_request('DELETE', f'/v1/assessments/{assessment_id}')
        demisto.results(f"Deleted assessment {assessment_id} successfully.")
    except Exception as e:
        if '403' in str(e):
            raise ValueError(f"Could not find the assessment {assessment_id}")
        else:
            raise


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
        elif command == 'attackiq-list-assessment-templates':
            list_templates_command()
        elif command == 'attackiq-list-assets':
            list_assets_command()
        elif command == 'attackiq-create-assessment':
            create_assessment_command()
        elif command == 'attackiq-add-assets-to-assessment':
            add_assets_to_assessment()
        elif command == 'attackiq-delete-assessment':
            delete_assessment_command()
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
if __name__ in ("__builtin__", "builtins", "__main__"):
    main()
