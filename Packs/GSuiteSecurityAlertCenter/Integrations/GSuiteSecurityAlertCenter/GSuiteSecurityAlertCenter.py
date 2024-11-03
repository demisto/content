from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''

import urllib3
import traceback
from datetime import datetime
from typing import Any
from collections.abc import Callable

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DEFAULT_FIRST_FETCH = '3 days'
DEFAULT_MAX_FETCH = 15
BASE_URL = 'https://alertcenter.googleapis.com/'
NEXT_PAGE_TOKEN = '### Next Page Token:\n{}\n'
LIST_FEEDBACK_PAGE_SIZE = 50

URL_SUFFIX: dict[str, str] = {
    'LIST_ALERTS': 'v1beta1/alerts',
    'FEEDBACK': 'v1beta1/alerts/{0}/feedback',
    'GET_ALERT': 'v1beta1/alerts/{}',
    'BATCH_DELETE': 'v1beta1/alerts:batchDelete',
    'BATCH_RECOVER': 'v1beta1/alerts:batchUndelete'
}

OUTPUT_PATHS = {
    'ALERT': 'GSuiteSecurityAlert.Alert(val.alertId == obj.alertId)',
    'TOKEN': 'GSuiteSecurityAlert.PageToken.Alert(val.name == val.name)',
    'FEEDBACK': 'GSuiteSecurityAlert.Feedback',
    'BATCH_DELETE_SUCCESS': 'GSuiteSecurityAlert.Delete.successAlerts(val.id && val.id == obj.id)',
    'BATCH_DELETE_FAILED': 'GSuiteSecurityAlert.Delete.failedAlerts(val.id && val.id == obj.id)',
    'BATCH_RECOVER_SUCCESS': 'GSuiteSecurityAlert.Recover.successAlerts(val.id && val.id == obj.id)',
    'BATCH_RECOVER_FAILED': 'GSuiteSecurityAlert.Recover.failedAlerts(val.id && val.id == obj.id)'
}

MESSAGES: dict[str, str] = {
    'TEST_CONNECTIVITY_FAILED_ERROR': 'Test connectivity failed. Check the configuration parameters provided.',
    'INTEGER_ERROR': 'The argument {} must be a positive integer.',
    'MAX_INCIDENT_ERROR': 'Value of maximum number of incidents to fetch every time must be a positive integer '
                          'between 1 and 1000.',
    'INVALID_FEEDBACK_TYPE_ERROR': 'The given value for feedback type is invalid. Valid feedback types: '
                                   'ALERT_FEEDBACK_TYPE_UNSPECIFIED, NOT_USEFUL, SOMEWHAT_USEFUL, VERY_USEFUL.',
    'NO_RECORDS_FOUND': 'No {} were found for the given argument(s).',
    'MISSING_REQUIRED_ARGUMENTS_ERROR': 'Required argument(s): {}.',
    'INVALID_FILTER': 'Invalid createTime parameter in Filter. To fetch alerts using createTime, use the first fetch '
                      'time interval parameter.',
    'INVALID_PARAM_VALUE_ERROR': 'The given value for {0} parameter is invalid.'
}

DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'
SCOPES: dict[str, list[str]] = {
    'ALERT': ['https://www.googleapis.com/auth/apps.alerts']
}
ALERT_FEEDBACK_TYPES = ['alert_feedback_type_unspecified', 'not_useful', 'somewhat_useful', 'very_useful']


def validate_date(first_fetch) -> str:
    """
    Check whether the date provided is valid.

    :type first_fetch: string
    :param first_fetch: date

    :return: raise ValueError if validation fails, else return parsed date.
    :rtype: str
    """
    date_time = arg_to_datetime(first_fetch, is_utc=True, settings={'STRICT_PARSING': True})
    if date_time:
        create_time = date_time.strftime(DATE_FORMAT)
    else:
        raise ValueError(MESSAGES['INVALID_PARAM_VALUE_ERROR'].format('first fetch time interval'))

    current_time = datetime.utcnow()
    date_time_obj = datetime.strptime(create_time, DATE_FORMAT)

    if date_time_obj > current_time:
        raise ValueError(MESSAGES['INVALID_PARAM_VALUE_ERROR'].format('first fetch time interval'))

    return create_time


def validate_params_for_fetch_incidents(params: dict[str, Any], last_run: dict) -> tuple[dict[str, Any], str]:
    """
    Validates parameters for fetch-incidents command.

    :param params: parameters dictionary.
    :param last_run: A dict with a key containing the latest incident created time we got
        from last fetch

    :return: A tuple containing two elements:
            params (``Dict[str, int]``): fetch incident parameters.
            last_fetch (``str``): updated last_fetch.
    """
    params = GSuiteClient.remove_empty_entities(params)

    # get user provided fetch_first interval
    first_fetch = params.get('first_fetch')
    first_fetch = DEFAULT_FIRST_FETCH if not first_fetch else first_fetch

    # Validate the first_fetch value
    create_time = validate_date(first_fetch)

    # get the last_fetch value
    last_fetch = last_run['last_fetch'] if last_run.get('last_fetch') else create_time

    # get the user provided max_fetch value
    max_fetch = params.get('max_fetch', DEFAULT_MAX_FETCH)
    max_fetch = GSuiteClient.validate_get_int(max_fetch, limit=1000, message=MESSAGES['MAX_INCIDENT_ERROR'])

    next_page_token = last_run.get('next_page_token', '')

    # set the filter with last_fetch value
    alert_filter = f'createTime>"{last_fetch}"'

    # get user provided filter value and validate it
    advance_filter = params.get('filter', '').replace("'", '"')
    if 'createTime' in advance_filter or 'create_time' in advance_filter:
        raise ValueError(MESSAGES['INVALID_FILTER'])

    if 'type' not in advance_filter:
        alert_types = params.get('alert_type', [])

        for index in range(0, len(alert_types)):
            alert_types[index] = alert_types[index].replace("\"", "").replace("'", "").strip()
            if index == 0:
                alert_filter += f' AND (type="{alert_types[index]}"'
            else:
                alert_filter += f' OR type="{alert_types[index]}"'

        if '(' in alert_filter:
            alert_filter += ')'

    if advance_filter != '':
        alert_filter += f' AND {advance_filter}'

    # If next_page_token is present replace filter with filter present in last_run as API does not support
    # change in filter.
    if next_page_token:
        alert_filter = last_run.get('alert_filter', '')

    updated_params = {
        'filter': alert_filter,
        'pageSize': max_fetch,
        'pageToken': next_page_token,
        'orderBy': 'createTime asc'
    }
    return GSuiteClient.remove_empty_entities(updated_params), last_fetch


def validate_params_for_list_alerts(args: dict[str, str]) -> dict[str, Any]:
    """
    Prepares arguments for list alerts.

    :param args: Command arguments.
    :return: Prepared params.
    :raises ValueError: If there any invalid value of argument.
    """
    page_size = args.get('page_size', '')
    page_size = int(page_size) if page_size == '0' else \
        GSuiteClient.validate_get_int(page_size, message=MESSAGES['INTEGER_ERROR'].format('page_size'))

    alert_filter = args.get('filter', '')
    if alert_filter:
        alert_filter = alert_filter.replace("'", '"')

    params = {
        'pageToken': args.get('page_token', ''),
        'pageSize': page_size,
        'filter': alert_filter,
        'orderBy': args.get('order_by', '')
    }

    return GSuiteClient.remove_empty_entities(params)


def prepare_hr_for_alerts(alerts: list[dict[str, Any]], header: str) -> str:
    """
    Prepare the Human readable info for alerts command.

    :param alerts: The alerts data.
    :param header: Header of the hr table.
    :return: Human readable.
    """

    hr_list = []
    for record in alerts:

        hr_record = {
            'Alert ID': record.get('alertId', ''),
            'Create Time': record.get('createTime', ''),
            'Update Time': record.get('updateTime', ''),
            'Alert Type': record.get('type', ''),
            'Source': record.get('source', ''),
            'Severity': record.get('metadata', {}).get('severity', ''),
            'Status': record.get('metadata', {}).get('status', '')
        }
        hr_list.append(hr_record)

    return tableToMarkdown(header, hr_list, ['Alert ID', 'Alert Type', 'Source', 'Severity', 'Status', 'Create Time',
                                             'Update Time'], removeNull=True)


def prepare_hr_for_alert_feedback(feedbacks: list[dict[str, Any]]) -> str:
    """
    Prepare the Human readable info for create alert feedback command.

    :param feedbacks: The created feedback data.
    :return: Human readable.
    """

    hr_table: list[dict[str, Any]] = []
    for feedback in feedbacks:
        hr_table.append({
            'Feedback ID': feedback.get('feedbackId', ''),
            'Alert ID': feedback.get('alertId', ''),
            'Create Time': feedback.get('createTime', ''),
            'Feedback Type': feedback.get('type', ''),
            'Email': feedback.get('email', '')
        })
    return tableToMarkdown('Feedback Details', hr_table,
                           ['Feedback ID', 'Alert ID', 'Create Time', 'Feedback Type', 'Email'], removeNull=True)


def prepare_hr_for_batch_command(response: dict[str, Any], method: str) -> str:
    """
    Prepare the Human readable info for batch delete and recover alerts command.

    :param response: The delete and recover alerts data.
    :param method: To delete or recover alerts.
    :return: Human readable.
    """

    hr_list: list[dict[str, Any]] = []
    for each_success_id in response.get('successAlertIds', []):
        hr_record = {
            'Alert ID': each_success_id,
            'Status': 'Success'
        }
        hr_list.append(hr_record)

    for each_fail_key, val in response.get('failedAlertStatus', {}).items():
        hr_record = {
            'Alert ID': each_fail_key,
            'Status': f'Fail ({val.get("message")})'
        }
        hr_list.append(hr_record)

    return tableToMarkdown(
        name=method,
        t=hr_list,
        headers=['Alert ID', 'Status'],
        removeNull=True
    )


def create_custom_context_for_batch_command(response: dict[str, Any]) -> tuple[list, list]:
    """
    Prepare the custom Context Output for batch delete and recover alerts command.

    :param response: The batch delete and recover alerts data.
    :return: Success alerts list and failed alerts list
    """
    success_list: list = []
    failed_list: list = []
    for each_id in response.get('successAlertIds', []):
        success_obj: dict[str, Any] = {
            'id': each_id,
            'status': 'Success'
        }
        success_list.append(success_obj)

    for failed_key, value in response.get('failedAlertStatus', {}).items():
        failed_alert_id: dict[str, Any] = {
            'id': failed_key,
            'status': 'Fail',
            'code': value.get('code'),
            'message': value.get('message', '')
        }
        failed_list.append(failed_alert_id)

    return success_list, failed_list


def check_required_arguments(required_arguments: list[str], args: dict[str, Any]):
    """
    Checks if the required arguments after trimming the spaces are non empty

    :param required_arguments: List of required arguments in a command
    :param args: command parameters
    :return: Raises ValueError if any required arguments are missing
    """
    missing_args = []
    for arg in required_arguments:
        if arg not in args:
            missing_args.append(arg)
    if missing_args:
        raise ValueError(MESSAGES['MISSING_REQUIRED_ARGUMENTS_ERROR'].format(", ".join(missing_args)))


''' COMMAND FUNCTIONS '''


@logger
def test_module(gsuite_client, last_run: dict, params: dict[str, Any]) -> str:
    """
    Performs test connectivity by valid http response

    :param gsuite_client: client object which is used to get response from api.
    :param last_run: Demisto last run dictionary.
    :param params: configuration parameters.

    :return: raise ValueError if any error occurred during connection
    :raises DemistoException: If there is any other issues while making the http call.
    """
    if params.get('isFetch'):
        fetch_incidents(gsuite_client, last_run, params, is_test=True)
    else:
        list_alerts_params = {
            'pageSize': 1,
        }
        gsuite_client.set_authorized_http(
            scopes=SCOPES['ALERT'],
            subject=params.get('admin_email_creds', {}).get('identifier') or params.get('admin_email', '')
        )
        gsuite_client.http_request(url_suffix=URL_SUFFIX['LIST_ALERTS'], method='GET', params=list_alerts_params)

        if not gsuite_client.credentials.valid:
            raise DemistoException(MESSAGES['TEST_CONNECTIVITY_FAILED_ERROR'])

    return 'ok'


@logger
def gsac_list_alerts_command(client, args: dict[str, str]) -> CommandResults:
    """
    List alerts from G Suite Security Alert center.

    :param client: Client object.
    :param args: Command arguments.

    :return: Command Result.
    """
    # Prepare params
    admin_email = args.get('admin_email')
    params = validate_params_for_list_alerts(args)

    # API Call
    client.set_authorized_http(scopes=SCOPES['ALERT'], subject=admin_email)
    response = client.http_request(url_suffix=URL_SUFFIX['LIST_ALERTS'], method='GET', params=params)

    total_records = response.get('alerts', [])
    if not total_records:
        return CommandResults(readable_output=MESSAGES['NO_RECORDS_FOUND'].format('alert(s)'))

    token_ec = {}

    # Creating human-readable
    readable_hr = prepare_hr_for_alerts(total_records, 'Alerts')
    if response.get('nextPageToken'):
        readable_hr += NEXT_PAGE_TOKEN.format(response.get('nextPageToken'))
        token_ec = {'name': 'gsac-alert-list', 'nextPageToken': response.get('nextPageToken')}

    # Creating entry context
    output = {
        OUTPUT_PATHS['ALERT']: total_records,
        OUTPUT_PATHS['TOKEN']: token_ec
    }

    output = GSuiteClient.remove_empty_entities(output)

    return CommandResults(
        outputs=output,
        readable_output=readable_hr,
        raw_response=response
    )


@logger
def gsac_get_alert_command(client, args: dict[str, str]) -> CommandResults:
    """
    Get a single alert from G Suite Security Alert center.

    :param client: Client object.
    :param args: Command arguments.

    :return: Command Result.
    """
    # Check if required arguments are present
    check_required_arguments(required_arguments=['alert_id'], args=args)

    # Prepare params
    admin_email = args.get('admin_email')
    alert_id = args.get('alert_id', '')

    # API Call
    client.set_authorized_http(scopes=SCOPES['ALERT'], subject=admin_email)
    response = client.http_request(url_suffix=URL_SUFFIX['GET_ALERT'].format(alert_id), method='GET')

    if not response:
        return CommandResults(readable_output=MESSAGES['NO_RECORDS_FOUND'].format('alert'))

    # Creating entry context
    custom_ec_for_alerts = GSuiteClient.remove_empty_entities(response)

    # Creating human-readable
    readable_hr = prepare_hr_for_alerts([response], 'Alert')

    return CommandResults(
        outputs_prefix='GSuiteSecurityAlert.Alert',
        outputs_key_field='alertId',
        outputs=custom_ec_for_alerts,
        readable_output=readable_hr,
        raw_response=response
    )


@logger
def gsac_batch_delete_alerts_command(client, args: dict[str, str]) -> CommandResults:
    """
    Performs batch delete operation on alerts.

    :param client: Client object.
    :param args: Command arguments.

    :return: Command Result.
    """
    # Check if required arguments are present
    check_required_arguments(required_arguments=['alert_id'], args=args)

    # Prepare params
    json_body: dict[str, Any] = {}
    admin_email = args.get('admin_email')

    ids = argToList(args.get('alert_id', []), ",")

    json_body['alertId'] = ids

    # API Call
    client.set_authorized_http(scopes=SCOPES['ALERT'], subject=admin_email)
    batch_delete_response = client.http_request(url_suffix=URL_SUFFIX['BATCH_DELETE'], method='POST',
                                                body=json_body)

    # Create entry context
    success_list, failed_list = create_custom_context_for_batch_command(batch_delete_response)
    custom_context: dict[str, Any] = {
        OUTPUT_PATHS['BATCH_DELETE_SUCCESS']: success_list,
        OUTPUT_PATHS['BATCH_DELETE_FAILED']: failed_list
    }

    # Create HR
    hr = prepare_hr_for_batch_command(batch_delete_response, 'Delete Alerts')

    return CommandResults(
        outputs=GSuiteClient.remove_empty_entities(custom_context),
        readable_output=hr,
        raw_response=batch_delete_response
    )


@logger
def gsac_batch_recover_alerts_command(client, args: dict[str, str]) -> CommandResults:
    """
    Performs batch recover operation on alerts.

    :param client: Client object.
    :param args: Command arguments.

    :return: Command Result.
    """
    # Check if required arguments are present
    check_required_arguments(required_arguments=['alert_id'], args=args)

    # Prepare params
    json_body: dict[str, Any] = {}
    admin_email = args.get('admin_email')

    ids = argToList(args.get('alert_id', []), ",")

    json_body['alertId'] = ids

    # API Call
    client.set_authorized_http(scopes=SCOPES['ALERT'], subject=admin_email)
    batch_recover_response = client.http_request(url_suffix=URL_SUFFIX['BATCH_RECOVER'], method='POST',
                                                 body=json_body)

    # Create entry context
    success_list, failed_list = create_custom_context_for_batch_command(batch_recover_response)
    custom_context: dict[str, Any] = {
        OUTPUT_PATHS['BATCH_RECOVER_SUCCESS']: success_list,
        OUTPUT_PATHS['BATCH_RECOVER_FAILED']: failed_list
    }

    # Create HR
    hr = prepare_hr_for_batch_command(batch_recover_response, 'Recover Alerts')

    return CommandResults(
        outputs=GSuiteClient.remove_empty_entities(custom_context),
        readable_output=hr,
        raw_response=batch_recover_response
    )


@logger
def gsac_create_alert_feedback_command(gsuite_client, args: dict[str, Any]) -> CommandResults:
    """
    Creates new feedback for an alert.

    :param gsuite_client: client object which is used to get response from api.
    :param args: command parameters.

    :return: CommandResults or raise ValueError if any error occurred.
    :raises DemistoException: If there is any other issues while making the http call.
    """

    # Check if required arguments are present
    check_required_arguments(required_arguments=['alert_id', 'feedback_type'], args=args)

    # Prepare Params
    json_body: dict[str, Any] = {}
    params: dict[str, Any] = {}
    admin_email = args.get('admin_email')

    if args['feedback_type'].lower() not in ALERT_FEEDBACK_TYPES:
        raise ValueError(MESSAGES['INVALID_FEEDBACK_TYPE_ERROR'])

    json_body['type'] = args['feedback_type']

    # API call
    gsuite_client.set_authorized_http(scopes=SCOPES['ALERT'], subject=admin_email)
    create_feedback_response = gsuite_client.http_request(
        url_suffix=URL_SUFFIX['FEEDBACK'].format(args['alert_id']),
        method='POST', body=json_body, params=params)

    # Create HR
    hr = prepare_hr_for_alert_feedback([create_feedback_response])

    # Create entry context
    custom_ec = gsuite_client.remove_empty_entities(create_feedback_response)

    return CommandResults(
        outputs_prefix=OUTPUT_PATHS['FEEDBACK'],
        outputs_key_field='feedbackId',
        outputs=custom_ec,
        readable_output=hr,
        raw_response=create_feedback_response
    )


@logger
def gsac_list_alert_feedback_command(gsuite_client, args: dict[str, Any]) -> CommandResults:
    """
    Lists all the feedback for an alert.

    :param gsuite_client: client object which is used to get response from api.
    :param args: command parameters.

    :return: CommandResults or raise ValueError if any error occurred.
    :raises DemistoException: If there is any other issues while making the http call.
    """

    # Check if required arguments are present
    check_required_arguments(required_arguments=['alert_id'], args=args)

    # Prepare params
    params: dict[str, Any] = {
        'filter': args.get('filter', '').replace("'", '"'),
    }
    admin_email = args.get('admin_email')
    page_size = args.get('page_size', LIST_FEEDBACK_PAGE_SIZE)
    page_size = GSuiteClient.validate_get_int(page_size, message=MESSAGES['INTEGER_ERROR'].format('page_size'))

    # API call
    gsuite_client.set_authorized_http(scopes=SCOPES['ALERT'], subject=admin_email)
    list_alert_feedback_response = gsuite_client.http_request(
        url_suffix=URL_SUFFIX['FEEDBACK'].format(args['alert_id']),
        method='GET',
        params=GSuiteClient.remove_empty_entities(params))

    no_records = len(list_alert_feedback_response.get('feedback', [])) == 0
    if no_records:
        return CommandResults(readable_output=MESSAGES['NO_RECORDS_FOUND'].format('feedback(s)'))

    list_alert_feedback_response["feedback"] = list_alert_feedback_response["feedback"][0:page_size]
    # Create HR
    hr = prepare_hr_for_alert_feedback(list_alert_feedback_response["feedback"])

    # Create entry context
    custom_ec = gsuite_client.remove_empty_entities(list_alert_feedback_response["feedback"])

    return CommandResults(
        outputs_prefix=OUTPUT_PATHS['FEEDBACK'],
        outputs_key_field='feedbackId',
        outputs=custom_ec,
        readable_output=hr,
        raw_response=list_alert_feedback_response
    )


@logger
def fetch_incidents(client, last_run: dict, params: dict, is_test: bool = False) -> \
        tuple[list | None, dict | None]:
    """
    This function is called for fetching incidents.
    This function gets all alerts, then after get latest feedback for each alert.
    This function will execute each interval (default is 1 minute).

    :param client: Client object.
    :param last_run: A dict with a key containing the latest incident created time we got
        from last fetch
    :param params: arguments for fetch-incident.
    :param is_test: True if fetch-incident is called from test-module.

    :return: A tuple containing two elements:
            next_run (``Dict[str, int]``): Contains the timestamp that will be
                    used in ``last_run`` on the next fetch.
            incidents (``List[dict]``): List of incidents that will be created in XSOAR.
    """

    admin_email = params.get('admin_email_creds', {}).get('identifier') or params.get('admin_email')

    fetch_feedback = params.get('fetch_feedback', False)
    # Validate arguments
    params, last_fetch = validate_params_for_fetch_incidents(params, last_run)

    # Fetch Alerts API call
    client.set_authorized_http(scopes=SCOPES['ALERT'], subject=admin_email)
    response = client.http_request(url_suffix=URL_SUFFIX['LIST_ALERTS'], method='GET', params=params)

    alerts = response.get('alerts', [])
    next_page_token = response.get('nextPageToken', '')

    demisto.info(f'[GSAC ALERT]: Request URL: {BASE_URL}{URL_SUFFIX["LIST_ALERTS"]}')
    demisto.info(f'[GSAC ALERT]: Next Token: {next_page_token}')

    incidents: list[dict[str, Any]] = []

    # Prepare incidents data
    for alert in alerts:
        if fetch_feedback:
            # Fetch Alert Feedback API call
            feedback_response = client.http_request(url_suffix=URL_SUFFIX['FEEDBACK'].format(alert.get('alertId')),
                                                    method='GET')
            feedback_response = feedback_response.get('feedback', [])
            if len(feedback_response) > 0:
                # Fetch latest feedback
                alert['feedback'] = feedback_response[0]
        incident = {
            'name': f'{alert.get("type")} - {alert.get("source")}',
            'occurred': alert.get('createTime'),
            'rawJSON': json.dumps(alert)
        }
        incidents.append(incident)

    # Fetch createTime of latest alert
    if len(alerts) > 0:
        timestamp = alerts[-1]['createTime']
    else:
        timestamp = last_fetch

    if is_test:
        return None, None
    return incidents, {'last_fetch': timestamp, 'next_page_token': next_page_token,
                       'alert_filter': params['filter']}


def main() -> None:
    """
         PARSE AND VALIDATE INTEGRATION PARAMS
    """

    # Commands dictionary
    commands: dict[str, Callable] = {
        'gsac-alert-list': gsac_list_alerts_command,
        'gsac-alert-feedback-create': gsac_create_alert_feedback_command,
        'gsac-alert-get': gsac_get_alert_command,
        'gsac-alert-delete': gsac_batch_delete_alerts_command,
        'gsac-alert-feedback-list': gsac_list_alert_feedback_command,
        'gsac-alert-recover': gsac_batch_recover_alerts_command
    }
    command = demisto.command()
    demisto.info(f'Command being called is {command}')

    try:
        params = demisto.params()
        service_account_dict = GSuiteClient.safe_load_non_strict_json(
            params.get('admin_email_creds', {}).get('password')
            or params.get('user_service_account_json'))
        verify_certificate = not params.get('insecure', False)
        proxy = params.get('proxy', False)

        headers = {
            'Content-Type': 'application/json'
        }

        # prepare client class object
        gsuite_client = GSuiteClient(service_account_dict,
                                     base_url=BASE_URL,
                                     verify=verify_certificate,
                                     proxy=proxy,
                                     headers=headers)

        # Trim the arguments
        args = GSuiteClient.strip_dict(demisto.args())

        # This is the call made when pressing the integration Test button.
        if demisto.command() == 'test-module':
            result = test_module(gsuite_client, {}, params)
            return_results(result)
        elif demisto.command() == 'fetch-incidents':
            incidents, next_run = fetch_incidents(gsuite_client,
                                                  last_run=demisto.getLastRun(),
                                                  params=params)

            demisto.setLastRun(next_run)
            demisto.incidents(incidents)
        elif command in commands:
            args['admin_email'] = params.get('admin_email_creds', {}).get('identifier') or params.get('admin_email', '')
            return_results(commands[command](gsuite_client, args))

    # Log exceptions
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


from GSuiteApiModule import *  # noqa: E402

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
