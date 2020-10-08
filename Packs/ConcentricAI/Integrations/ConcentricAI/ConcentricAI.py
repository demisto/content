from typing import Dict

import urllib3
from CommonServerPython import *
from datetime import datetime

# Disable insecure warnings
urllib3.disable_warnings()

http = urllib3.PoolManager()


'''Constants'''
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

'''Globals'''
AUTH_URL: str
QUERY_URL: str
CLIENT_ID: str
CLIENT_SECRET: str
DOMAIN: str
AUTHORIZATION: str
AUTH_HEADERS: dict
CLIENT_HEADERS: dict
VERIFY_CERT: bool
PROXY: bool
TENANT_ID: str
USERNAME: str
QUERY_HEADERS: dict
COOKIE: str
LAST_FETCH = None
RISK_RULES: dict
SCROLL_ID_INCIDENT: str
SCROLL_ID_FILE: str
SCROLL_ID_USER_DETAIL: str


def encoding(username, password):
    sample_string = username + ":" + password
    sample_string_bytes = sample_string.encode("ascii")
    base64_bytes = base64.b64encode(sample_string_bytes)
    base64_string = base64_bytes.decode("ascii")
    encoded_value = base64_string
    return encoded_value


def get_headers_for_login():

    headers_for_login = {
        'Authorization': AUTHORIZATION,
        'X-Domain': DOMAIN,
        'grant_type': 'client_credentials',
        'Content-Type': 'application/json'
       }
    return headers_for_login


def get_headers_for_query():
    headers_for_query = {
        'Cookie': COOKIE,
        'X-Domain': DOMAIN,
        'grant_type': 'client_credentials',
        'client_id': CLIENT_ID,
        'Content-Type': 'application/json'
    }
    return headers_for_query


def initialise_scrolls_and_rules():
    global SCROLL_ID_USER_DETAIL, SCROLL_ID_FILE, SCROLL_ID_INCIDENT, RISK_RULES

    SCROLL_ID_INCIDENT = ""
    SCROLL_ID_FILE = ""
    SCROLL_ID_USER_DETAIL = ""
    RISK_RULES = {}


def initialize_global_values():

    global AUTH_URL, COOKIE, AUTH_HEADERS, QUERY_HEADERS, QUERY_URL,\
        CLIENT_ID, CLIENT_SECRET, AUTH_HEADERS, DOMAIN, AUTHORIZATION

    CLIENT_ID = demisto.getParam('client_id')
    CLIENT_SECRET = demisto.getParam('client_secret')
    AUTH_URL = demisto.getParam('url')
    QUERY_URL = urljoin(demisto.getParam('url'), "/graphql-demisto")
    DOMAIN = demisto.getParam('domain')
    AUTHORIZATION = "Basic " + encoding(CLIENT_ID, CLIENT_SECRET)
    AUTH_HEADERS = get_headers_for_login()
    initialise_scrolls_and_rules()


'''
This is the client class that will have all the client login calls.
'''


class LoginClient(BaseClient):

    def fetch_api_token(self):
        res = self._http_request(
            method='GET',
            url_suffix='api/v1/login'
        )

        accessToken = res['accessToken']
        return accessToken


'''
This class handles all query elements.
'''


class QueryClient(BaseClient):

    def fetch_incidents(self, severity, from_time, to_time, pageIndex, loginClient: LoginClient):
        global SCROLL_ID_INCIDENT
        try:
            payload = {
                "query": "{ allAlerts(severity: [" + severity + ", high] timerange: [" + from_time + "," + to_time + "] pagination: { currentPage: " + pageIndex + " pageSize: 500 } _scroll_id: \"" + SCROLL_ID_INCIDENT + "\") { allContents{rows { cid risk_id name risk_timestamp service owner risk path } _scroll_id pagination } } }"
            }
            res = self._http_request(
                method='POST',
                json_data=payload,
                url_suffix='graphql-demisto'
            )

        except Exception as e:
            if str(e) == 'Error in API call [401] - Unauthorized\n':
                fetch_token(loginClient)
                res = self._http_request(
                    method='POST',
                    json_data=payload,
                    url_suffix='graphql-demisto'
                )
            else:
                raise Exception('Failed to pull incidents', e)

        return res

    def get_risk_rules(self, loginClient: LoginClient):
        try:
            payload = {
                "query": "{\n allAlerts(severity: [low, high] timerange: [0,1] pagination: { currentPage:1 pageSize: 1 }) { allContents{rows { cid } } riskRules { id, risk_name} } }"
            }
            res = self._http_request(
                method='POST',
                json_data=payload,
                url_suffix='graphql-demisto'
            )

        except Exception as e:
            if str(e) == 'Error in API call [401] - Unauthorized\n':
                fetch_token(loginClient)
                res = self._http_request(
                    method='POST',
                    json_data=payload,
                    url_suffix='graphql-demisto'
                )
            else:
                raise Exception('Failed to pull risk-rules', e)

        return res

    def get_file_information(self, loginClient: LoginClient, path: str):
        global SCROLL_ID_FILE
        try:
            payload = {
                "query": "{ allContents(filter: \"{\\\"and\\\": [{\\\"in\\\": [ { \\\"var\\\": \\\"path\\\"}, [\\\"" + path + "\\\"]] }]}\" pagination: { currentPage: 1 pageSize: 500 } _scroll_id: \"" + SCROLL_ID_FILE + "\") { allContents {rows {        retrieved_class        ccc_class        name        ownerDetails {          name        }        category        subcategory        service        type        dropped        dropped_reason        created_at        modified_at        duplicate        near_duplicate        misclass        size        path        url        entity_person        entity_org        entity_email        entity_bank_account        entity_credit_card        entity_date_of_birth        entity_driving_license        entity_health_insurance        entity_license_plate        entity_ssn        entity_tin        entity_passport        entity_address        pii           risk        risk_id        confidence        word_cloud        duplicate_contrib_cids        near_duplicate_contrib_cids        misclass_contrib_cid        pii_type      }  _scroll_id  pagination  }  }  }"
            }
            res = self._http_request(
                method='POST',
                json_data=payload,
                url_suffix='graphql-demisto'
            )

        except Exception as e:
            if str(e) == 'Error in API call [401] - Unauthorized\n':
                fetch_token(loginClient)
                res = self._http_request(
                    method='POST',
                    json_data=payload,
                    url_suffix='graphql-demisto'
                )
            else:
                raise Exception('Failed to pull file-information', e)

        return res

    def get_users_overview(self, loginClient: LoginClient):
        try:
            payload = {
                "query": "{\n  allContents: allContents(pagination: {currentPage: 1, pageSize: 1000} , aggregate: {fields: [ \"permitted_int_users\", \"permitted_ext_users\", \"permitted_grp_users\", \"permitted_orphans\"]}) {\n    allContents {\n  pagination\n   }\n    aggregations\n  }\n}\n"
            }
            res = self._http_request(
                method='POST',
                json_data=payload,
                url_suffix='graphql-demisto'
            )

        except Exception as e:
            if str(e) == 'Error in API call [401] - Unauthorized\n':
                fetch_token(loginClient)
                res = self._http_request(
                    method='POST',
                    json_data=payload,
                    url_suffix='graphql-demisto'
                )
            else:
                raise Exception('Failed to pull users-overview', e)

        return res

    def get_user_details(self, loginClient: LoginClient, user: str):
        global SCROLL_ID_USER_DETAIL
        try:
            payload = {
                "query": "{allContents( pagination: { currentPage: 1 pageSize: 500 } _scroll_id: \"" + SCROLL_ID_USER_DETAIL + "\" filter: \"{ \\\"and\\\": [{\\\"in\\\":[\\\"" + user + "\\\", {\\\"var\\\":\\\"entitlement.name\\\"}]}]}\" ){ allContents{ rows { name, path, permitted_int_users, permitted_ext_users, permitted_grp_users, permitted_orphans} pagination _scroll_id } aggregations } }"
            }

            res = self._http_request(
                method='POST',
                json_data=payload,
                url_suffix='graphql-demisto'
            )

        except Exception as e:
            if str(e) == 'Error in API call [401] - Unauthorized\n':
                fetch_token(loginClient)
                res = self._http_request(
                    method='POST',
                    json_data=payload,
                    url_suffix='graphql-demisto'
                )
            else:
                raise Exception('Failed to pull users-overview', e)

        return res


def convert_to_demisto_severity(severity: str) -> int:
    return {
        'low': 1,  # low severity
        'medium': 2,  # medium severity
        'high': 3,  # high severity
        'critical': 4   # critical severity
    }[severity]


def fetch_token(client: LoginClient):
    token = client.fetch_api_token()
    global COOKIE
    COOKIE = 'accessToken=' + token
    global QUERY_HEADERS
    QUERY_HEADERS = get_headers_for_query()


def get_rule_names(risk_id: List, risk_rules: dict):
    rule_names = None
    for id in risk_id:
        if id > 0:
            if risk_rules[str(id)]:
                if rule_names is None:
                    rule_names = risk_rules[str(id)]
                else:
                    rule_names = rule_names + "," + risk_rules[str(id)]

    return rule_names


def map_risk_rules(loginClient: LoginClient, queryClient: QueryClient):
    global RISK_RULES
    if len(RISK_RULES) == 0:
        res = queryClient.get_risk_rules(loginClient)
        risk_rules = res['data']['allAlerts']['riskRules']
        risk_dict = {}
        for rule in risk_rules:
            risk_dict[str(rule['id'])] = rule['risk_name']
        RISK_RULES = risk_dict

    return RISK_RULES


def transform_to_incidents(answers: list, risk_rules: dict):
    targets = []
    for answer in answers:
        target = {
            'cid': answer['cid'],
            'rule_name': get_rule_names(answer['risk_id'], risk_rules),
            'service': answer['service'],
            'name': answer['name'],
            'file-path': answer['path'],
            'owner': answer['owner'],
            'risk': answer['risk'],
            'risk_timestamp': answer['risk_timestamp']
        }
        targets.append(target)

    return targets


def filter_user_information(answers):
    int_users = answers['total_by_permitted_int_users']
    int_users = int_users['buckets']
    ext_users = answers['total_by_permitted_ext_users']
    ext_users = ext_users['buckets']
    grp_users = answers['total_by_permitted_grp_users']
    grp_users = grp_users['buckets']
    orphan_users = answers['total_by_permitted_orphans']
    orphan_users = orphan_users['buckets']

    result = {
        'internal-users': int_users,
        'external_users': ext_users,
        'group_users': grp_users,
        'orphan_users': orphan_users
    }
    return result


def transform_user_details(answer):
    target = {}
    if answer['path'] is not None:
        target['file-path'] = answer['path']
    if 'permitted_ext_users' in answer and answer['permitted_ext_users'] is not None:
        target['user-external'] = answer['permitted_ext_users']
    if 'permitted_grp_users' in answer and answer['permitted_grp_users'] is not None:
        target['users-group'] = answer['permitted_grp_users']
    if 'name' in answer and answer['name'] is not None:
        target['file-name'] = answer['name']
    if 'permitted_int_users' in answer and answer['permitted_int_users'] is not None:                      
        target['user-internal'] = answer['permitted_int_users']
    if 'permitted_orphans' in answer and answer['permitted_orphans'] is not None:                      
        target['users-orphans'] = answer['permitted_orphans']
    return target


def transform_file_information(target: dict, risk_dict: dict):

    if target['risk_id'] is not None:
        target['risk_names'] = get_rule_names(target['risk_id'], risk_dict)
    if 'risk_id' in target:
        target.pop('risk_id')
    if 'category' in target:
        target.pop('category')
    if 'duplicate_contrib_cids' in target:
        target.pop('duplicate_contrib_cids')
    if 'word_cloud' in target:
        target.pop('word_cloud')
    if 'confidence' in target:
        target.pop('confidence')
    if 'ownerDetails' in target:
        if target['ownerDetails'] is not None:
            target['ownerDetails'] = target['ownerDetails']['name']
    return target


def test_module(client: LoginClient):
    token = client.fetch_api_token()
    if token:
        return 'ok'


def fetch_incidents(loginClient: LoginClient, queryClient: QueryClient, last_run: Dict[str, int]):

    last_fetch = last_run.get('last_fetch', None)
    if last_fetch is None:
        from_time = 0
        to_time = int(datetime.now().timestamp() * 1000)
        last_fetch = int(to_time)
        to_time = last_fetch
    else:
        last_fetch = int(last_fetch)
        from_time = last_fetch
        to_time = int(datetime.now().timestamp() * 1000)

    min_severity = demisto.getParam('min_severity')
    if min_severity is None:
        min_severity = 'low'

    flag = True
    newAlerts = True
    pageIndex = 1
    answers: list = []
    global SCROLL_ID_INCIDENT
    total_count = 0
    max_records = None

    while(flag == True):
        res = queryClient.fetch_incidents(min_severity, str(from_time), str(to_time), str(pageIndex), loginClient)
        response = res['data']['allAlerts']['allContents']['rows']
        if max_records is None:
            max_records = res['data']['allAlerts']['allContents']['pagination']['totalRecords']
        SCROLL_ID_INCIDENT = res['data']['allAlerts']['allContents']['_scroll_id']
        count = len(response)
        if(count == 0):
            flag = False
            if(total_count == 0):
                newAlerts = False
        else:
            answers.extend(response)
            total_count = len(answers)
            pageIndex = pageIndex+1
            if total_count == max_records:
                break

    incidents: List = []
    next_run = {'last_fetch': last_fetch}
    SCROLL_ID_INCIDENT = ""
    if newAlerts == False:
        return next_run, incidents

    risk_dict = map_risk_rules(loginClient, queryClient)
    targets = transform_to_incidents(answers, risk_dict)

    for row in targets:
        t = datetime.fromtimestamp(int(row['risk_timestamp']) / 1000)
        inced_time = t.strftime(DATE_FORMAT)
        incident = {
            'name': row['name'],
            'occurred': inced_time,
            'severity': convert_to_demisto_severity(row['risk']),
            'rawJSON': json.dumps(row)
        }
        incidents.append(incident)

    return next_run, incidents


def fetch_file_information(loginClient: LoginClient, queryClient: QueryClient, path: str, name: str):

    flag = True
    global SCROLL_ID_FILE
    answers: list = []
    max_records = None

    while(flag == True):
        res = queryClient.get_file_information(loginClient, path)
        response = res['data']['allContents']['allContents']['rows']
        if max_records is None:
            max_records = res['data']['allContents']['allContents']['pagination']['totalRecords']
        SCROLL_ID_FILE = res['data']['allContents']['allContents']['_scroll_id']
        count = len(response)
        if count == 0:
            flag = False
        else:
            answers.extend(response)
            total_count = len(answers)
            if total_count == max_records:
                break

    SCROLL_ID_FILE = ""
    answer = {}
    for entry in answers:
        if entry['name'] is not None and entry['name'] == name:
            answer = entry
            break

    if len(answer) == 0:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n No file named {name} at path {path}')

    target = {}

    for props in answer:
        if answer[props] is not None:
            target[props] = answer[props]

    risk_dict = map_risk_rules(loginClient, queryClient)
    target = transform_file_information(target, risk_dict)
    readable_output = tableToMarkdown('Information List', target)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Concentric.info',
        outputs_key_field='info',
        outputs=target
    )


def get_users_overview(loginClient: LoginClient, queryClient: QueryClient):

    res = queryClient.get_users_overview(loginClient)
    answers = res['data']['allContents']['aggregations']
    result = filter_user_information(answers)
    readable_output = tableToMarkdown('Users Overview', result)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Concentric.info',
        outputs_key_field='info',
        outputs=result
    )


def get_user_details(loginClient: LoginClient, queryClient: QueryClient, user: str):
    flag = True
    global SCROLL_ID_USER_DETAIL
    answers: list = []
    max_records = None

    while(flag == True):
        res = queryClient.get_user_details(loginClient, user)
        response = res['data']['allContents']['allContents']['rows']
        if max_records is None:
            max_records = res['data']['allContents']['allContents']['pagination']['totalRecords']
        SCROLL_ID_USER_DETAIL = res['data']['allContents']['allContents']['_scroll_id']
        count = len(response)
        if(count == 0):
            flag = False
        else:
            answers.extend(response)
            total_count = len(answers)
            if total_count == max_records:
                break

    SCROLL_ID_USER_DETAIL = ""
    results = []
    for answer in answers:
        target = transform_user_details(answer)
        results.append(target)

    readable_output = tableToMarkdown('Users Details', results)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Concentric.info',
        outputs_key_field='info',
        outputs=results
    )


def main() -> None:

    initialize_global_values()
    headers = AUTH_HEADERS
    base_url = urljoin(demisto.params()['url'])
    verify_certificate = not demisto.params().get('insecure', True)
    demisto.debug(f'Command being called is {demisto.command()}')
    proxy = demisto.params().get('proxy', False)
    loginClient = LoginClient(
        base_url=base_url,
        verify=verify_certificate,
        headers=headers,
        proxy=proxy)
    fetch_token(loginClient)
    global QUERY_HEADERS
    queryClient = QueryClient(
        base_url=base_url,
        headers=QUERY_HEADERS,
        proxy=proxy)

    try:
        # This is the call made when pressing the integration Test button.
        if demisto.command() == 'test-module':
            result = test_module(loginClient)
            return_results(result)

        # Set and define the fetch incidents command to run after activated via integration settings.
        elif demisto.command() == 'fetch-incidents':
            last_run = demisto.getLastRun()
            next_run, incidents = fetch_incidents(loginClient, queryClient, last_run)
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        # this will fetch all file information
        elif demisto.command() == 'get-file-details':
            path = demisto.getArg('path')
            name = demisto.getArg('file-name')
            result = fetch_file_information(loginClient, queryClient, path, name)
            return_results(result)

        # this will fetch all information about users-overview.
        elif demisto.command() == "get-users-overview":
            result = get_users_overview(loginClient, queryClient)
            return_results(result)

        # this will fetch all user-details
        elif demisto.command() == "get-user-details":
            user = demisto.getArg('user')
            result = get_user_details(loginClient, queryClient, user)
            return_results(result)

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
