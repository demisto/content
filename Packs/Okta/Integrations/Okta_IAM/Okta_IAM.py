import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import urllib3


# Disable insecure warnings
urllib3.disable_warnings()

'''CONSTANTS'''

BATCH_SIZE = 2000
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
DEPROVISIONED_STATUS = 'DEPROVISIONED'
USER_IS_DISABLED_MSG = 'User is already disabled.'
USER_IS_DISABLED_ERROR = 'E0000007'
ERROR_CODES_TO_SKIP = [
    'E0000016',  # user is already enabled
    USER_IS_DISABLED_ERROR
]
ERROR_CODES_TO_RETURN_ERROR = [
    'E0000047',  # rate limit - resets after 1 minute
]

FETCH_QUERY_EXCEPTION_MSG = 'If you marked the "Query only application events configured in IAM Configuration" ' \
                            'checkbox in the instance configuration, you must add at least one application in ' \
                            'the IAM Configuration incident before fetching logs from Okta. ' \
                            'Alternatively, you can unmark this checkbox and provide a ' \
                            '"Fetch Query Filter" parameter instead.'
GET_USER_ATTRIBUTES = ['id', 'login', 'email']

MAX_LOGS_LIMIT = 1000

'''CLIENT CLASS'''


class Client(BaseClient):
    """
    Okta IAM Client class that implements logic to authenticate with Okta.
    """

    def test_connection(self):
        uri = 'users/me'
        self._http_request(method='GET', url_suffix=uri)

    def get_user(self, filter_name: str, filter_value: str):
        filter_name = filter_name if filter_name == 'id' else f'profile.{filter_name}'
        uri = 'users'
        query_params = {
            'filter': f'{filter_name} eq "{filter_value}"'
        }

        res = self._http_request(
            method='GET',
            url_suffix=uri,
            params=query_params
        )

        if res and len(res) == 1:
            return res[0]
        return None

    def deactivate_user(self, user_id):
        uri = f'users/{user_id}/lifecycle/deactivate'
        self._http_request(
            method="POST",
            url_suffix=uri
        )

    def activate_user(self, user_id):
        query_params = {'sendEmail': 'false'}
        uri = f'users/{user_id}/lifecycle/activate'
        self._http_request(
            method="POST",
            url_suffix=uri,
            params=query_params
        )

    def create_user(self, user_data):
        # create a user in staged mode (not active)
        body = {
            'profile': user_data
        }
        uri = 'users'
        query_params = {
            'activate': 'false',
            'provider': 'true'
        }
        res = self._http_request(
            method='POST',
            url_suffix=uri,
            json_data=body,
            params=query_params
        )
        return res

    def update_user(self, user_id, user_data):
        body = {
            'profile': user_data
        }
        uri = f'users/{user_id}'
        res = self._http_request(
            method='POST',
            url_suffix=uri,
            json_data=body
        )
        return res

    def get_okta_fields(self):
        okta_fields = {}
        uri = 'meta/schemas/user/default'
        res = self._http_request(
            method='GET',
            url_suffix=uri
        )

        base_properties = res.get('definitions', {}).get('base', {}).get('properties', {})
        okta_fields.update({k: base_properties[k].get('title') for k in base_properties})

        custom_properties = res.get('definitions', {}).get('custom', {}).get('properties', {})
        okta_fields.update({k: custom_properties[k].get('title') for k in custom_properties})

        return okta_fields

    def http_request(self, method, url_suffix, full_url=None, params=None, data=None, headers=None):
        if headers is None:
            headers = self._headers
        full_url = full_url if full_url else urljoin(self._base_url, url_suffix)

        res = requests.request(
            method,
            full_url,
            verify=self._verify,
            headers=headers,
            params=params,
            json=data
        )
        return res

    def search_group(self, group_name):
        uri = 'groups'
        query_params = {
            'q': encode_string_results(group_name)
        }
        return self.http_request(
            method="GET",
            url_suffix=uri,
            params=query_params
        )

    def get_group_by_id(self, group_id):
        uri = f'groups/{group_id}'
        return self.http_request(
            method='GET',
            url_suffix=uri
        )

    def get_group_members(self, group_id):
        uri = f'groups/{group_id}/users'
        return self.get_paged_results(uri)

    def get_paged_results(self, uri, query_param=None):
        response = self.http_request(
            method="GET",
            url_suffix=uri,
            params=query_param
        )
        paged_results = response.json()
        if response.status_code != 200:
            raise Exception(
                f'Error occurred while calling Okta API: {response.request.url}. Response: {response.json()}')
        while "next" in response.links and len(response.json()) > 0:
            next_page = response.links.get("next").get("url")
            response = self._http_request(
                method="GET",
                full_url=next_page,
                url_suffix=''
            )
            if response.status_code != 200:
                raise Exception(
                    f'Error occurred while calling Okta API: {response.request.url}. Response: {response.json()}')
            paged_results += response.json()
        return paged_results

    def get_app_user_assignment(self, application_id, user_id):
        uri = f'/apps/{application_id}/users/{user_id}'
        res = self._http_request(
            method='GET',
            url_suffix=uri,
            resp_type='response',
            ok_codes=(200, 404)
        )
        return res

    def list_user_apps(self, user_id):
        uri = 'apps'
        query_params = {
            'filter': f'user.id eq "{user_id}"'
        }
        res = self._http_request(
            method='GET',
            url_suffix=uri,
            params=query_params
        )
        return res

    def list_apps(self, query, page, limit):
        query_params = {
            'q': query,
            'limit': limit
        }

        curr_page = 0
        apps_batch, next_page = self.list_apps_batch(url_suffix='/apps', params=query_params)

        while apps_batch and curr_page != page:
            curr_page += 1
            apps_batch, next_page = self.list_apps_batch(full_url=next_page)

        if not apps_batch:
            apps_batch = []
        return apps_batch

    def list_apps_batch(self, url_suffix='', params=None, full_url=''):
        """ Gets a batch of apps from Okta.
            Args:
                url_suffix (str): The apps API endpoint.
                params (dict): The API query params.
                full_url (str): The full url retrieved from the last API call.

            Return:
                apps_batch (dict): The logs batch.
                next_page (str): URL for next API call (equals '' on last batch).
        """
        if not url_suffix and not full_url:
            return None, None

        res = self._http_request(
            method='GET',
            url_suffix=url_suffix,
            params=params,
            full_url=full_url,
            resp_type='response'
        )

        logs_batch = res.json()
        next_page = res.links.get('next', {}).get('url')

        return logs_batch, next_page

    def get_logs(self, next_page=None, last_run_time=None, time_now=None,
                 query_filter=None, auto_generate_filter=False, context=None, limit=None):
        logs = []

        uri = 'logs'

        if auto_generate_filter:
            query_filter = get_query_filter(context)

        params = {
            'filter': query_filter,
            'since': last_run_time,
            'until': time_now,
            'limit': limit
        }
        limit = int(limit) if limit else None
        if limit and limit <= MAX_LOGS_LIMIT:
            return self._http_request(
                method='GET',
                url_suffix=uri,
                params=params,
            ), None

        if limit and limit > MAX_LOGS_LIMIT:
            params['limit'] = MAX_LOGS_LIMIT

        logs_batch, next_page = self.get_logs_batch(url_suffix=uri, params=params, full_url=next_page)

        try:
            while logs_batch:
                logs.extend(logs_batch)
                if limit and len(logs) > limit:
                    return logs[:limit], next_page
                logs_batch, next_page = self.get_logs_batch(full_url=next_page)
        except DemistoException as e:
            # in case of too many API calls, we return what we got and save the next_page for next fetch
            if not is_rate_limit_error(e):
                raise e

        return logs, next_page

    def get_logs_batch(self, url_suffix='', params=None, full_url=''):
        """ Gets a batch of logs from Okta.
            Args:
                url_suffix (str): The logs API endpoint.
                params (dict): The API query params.
                full_url (str): The full url retrieved from the last API call. Preferred over url_suffix if not empty.

            Return:
                logs_batch (dict): The logs batch.
                next_page (str): URL for next API call (equals '' on last batch).
        """
        if not url_suffix and not full_url:
            return None, None

        res = self._http_request(
            method='GET',
            url_suffix=url_suffix,
            params=params,
            full_url=full_url,
            resp_type='response'
        )

        logs_batch = res.json()
        next_page = res.links.get('next', {}).get('url')

        return logs_batch, next_page


'''HELPER FUNCTIONS'''


def get_all_user_profiles():
    query = 'type:"User Profile"'
    email_to_user_profile = {}

    user_profiles: List[dict] = []
    search_indicators = IndicatorsSearcher(query=query, size=BATCH_SIZE)
    for user_profile_res in search_indicators:
        user_profiles.extend(user_profile_res.get('iocs') or [])

    for user_profile in user_profiles:
        user_profile = user_profile.get('CustomFields', {})
        email_to_user_profile[user_profile.get('email')] = user_profile

    return email_to_user_profile


def get_event_username(log_entry):
    for target in log_entry.get('target', []):
        if target.get('type') == 'User':
            return target.get('alternateId')
    return None


def should_drop_event(log_entry, email_to_user_profile):
    """ Returns a boolean value indicates whether the incident should be dropped.

    Args:
        log_entry (dict): The log entry.

    Returns:
        (bool) True iff the event should be dropped.
    """
    username = get_event_username(log_entry)
    if username is not None and email_to_user_profile.get(username) is None:
        demisto.info(f'Dropping incident for user with username {username} - '
                     f'User Profile does not exist in XSOAR.')
        return True
    return False


def add_user_profile_data_to_entry(log_entry, email_to_user_profile):
    username = get_event_username(log_entry)
    user_profile = email_to_user_profile.get(username, {})
    log_entry.update(user_profile)
    log_entry['UserProfile'] = user_profile


def get_query_filter(context):
    iam_configuration = context.get('IAMConfiguration', [])
    if not iam_configuration:
        raise DemistoException(FETCH_QUERY_EXCEPTION_MSG)

    application_ids = [row['ApplicationID'] for row in iam_configuration]

    query_filter = '(eventType eq "application.user_membership.add" ' \
                   'or eventType eq "application.user_membership.remove") and'

    query_filter += '(' + ' or '.join([f'target.id co "{app_id}"' for app_id in application_ids]) + ')'

    return query_filter


def is_rate_limit_error(e):
    if hasattr(e, 'res') and e.res is not None:
        return e.res.status_code == 429
    return False


def handle_exception(user_profile, e, action, okta_user=None):
    """ Handles failed responses from Okta API by setting the User Profile object with the results.

    Args:
        user_profile (IAMUserProfile): The User Profile object.
        e (Exception): The exception error. If DemistoException, holds the response json.
        action (IAMActions): An enum represents the current action (get, update, create, etc).
    """
    if e.__class__ is DemistoException and hasattr(e, 'res') and e.res is not None:
        try:
            resp = e.res.json()
            error_code = resp.get('errorCode')
            error_message = get_error_details(resp)
        except ValueError:
            error_code = e.res.status_code
            error_message = str(e)
    else:
        error_code = ''
        error_message = str(e)

    if error_code == USER_IS_DISABLED_ERROR:
        user_profile.set_user_is_already_disabled(okta_user)

    elif error_code in ERROR_CODES_TO_SKIP:
        user_profile.set_result(action=action,
                                skip=True,
                                skip_reason=error_message)
    else:
        should_return_error = error_code in ERROR_CODES_TO_RETURN_ERROR
        user_profile.set_result(action=action,
                                success=False,
                                return_error=should_return_error,
                                error_code=error_code,
                                error_message=error_message)

    demisto.error(traceback.format_exc())


def get_error_details(res):
    """ Parses the error details retrieved from Okta and outputs the resulted string.

    Args:
        res (dict): The data retrieved from Okta.

    Returns:
        (str) The parsed error details.
    """
    error_msg = f'{res.get("errorSummary")}. '
    causes = ''
    for idx, cause in enumerate(res.get('errorCauses', []), 1):
        causes += f'{idx}. {cause.get("errorSummary")}\n'
    if causes:
        error_msg += f'Reason:\n{causes}'
    return error_msg


'''COMMAND FUNCTIONS'''


def test_module(client, is_fetch, fetch_query_filter, auto_generate_query_filter, context, first_fetch_str):
    if is_fetch:
        if auto_generate_query_filter:
            get_query_filter(context)  # will raise an exception if configuration doesn't exist
        elif not fetch_query_filter:
            raise DemistoException(FETCH_QUERY_EXCEPTION_MSG)
    try:
        dateparser.parse(first_fetch_str).strftime(DATE_FORMAT)  # type: ignore
    except AttributeError:
        raise DemistoException('First fetch timestamp parameter is not in the correct format.')

    client.test_connection()

    return_results('ok')


def get_mapping_fields_command(client):
    okta_fields = client.get_okta_fields()
    incident_type_scheme = SchemeTypeMapping(type_name=IAMUserProfile.DEFAULT_INCIDENT_TYPE)

    for field, description in okta_fields.items():
        incident_type_scheme.add_field(field, description)

    return GetMappingFieldsResponse([incident_type_scheme])


def get_user_command(client, args, mapper_in, mapper_out):
    user_profile = IAMUserProfile(user_profile=args.get('user-profile'), mapper=mapper_out,
                                  incident_type=IAMUserProfile.UPDATE_INCIDENT_TYPE)
    try:
        iam_attr, iam_attr_value = user_profile.get_first_available_iam_user_attr(GET_USER_ATTRIBUTES)
        okta_user = client.get_user(iam_attr, iam_attr_value)
        if not okta_user:
            error_code, error_message = IAMErrors.USER_DOES_NOT_EXIST
            user_profile.set_result(action=IAMActions.GET_USER,
                                    success=False,
                                    error_code=error_code,
                                    error_message=error_message)
        else:
            user_profile.update_with_app_data(okta_user, mapper_in)
            user_profile.set_result(
                action=IAMActions.GET_USER,
                success=True,
                active=okta_user.get('status') != DEPROVISIONED_STATUS,
                iden=okta_user.get('id'),
                email=okta_user.get('profile', {}).get('email'),
                username=okta_user.get('profile', {}).get('login'),
                details=okta_user
            )

    except Exception as e:
        handle_exception(user_profile, e, IAMActions.GET_USER)

    return user_profile


def disable_user_command(client, args, is_command_enabled, mapper_out):
    user_profile = IAMUserProfile(user_profile=args.get('user-profile'), mapper=mapper_out,
                                  incident_type=IAMUserProfile.UPDATE_INCIDENT_TYPE)
    okta_user = None
    if not is_command_enabled:
        user_profile.set_result(action=IAMActions.DISABLE_USER,
                                skip=True,
                                skip_reason='Command is disabled.')
    else:
        try:
            iam_attr, iam_attr_value = user_profile.get_first_available_iam_user_attr(GET_USER_ATTRIBUTES)
            okta_user = client.get_user(iam_attr, iam_attr_value)
            if not okta_user:
                _, error_message = IAMErrors.USER_DOES_NOT_EXIST
                user_profile.set_result(action=IAMActions.DISABLE_USER,
                                        skip=True,
                                        skip_reason=error_message)
            else:
                client.deactivate_user(okta_user.get('id'))
                user_profile.set_result(
                    action=IAMActions.DISABLE_USER,
                    success=True,
                    active=False,
                    iden=okta_user.get('id'),
                    email=okta_user.get('profile', {}).get('email'),
                    username=okta_user.get('profile', {}).get('login'),
                    details=okta_user
                )

        except Exception as e:
            handle_exception(user_profile, e, IAMActions.DISABLE_USER, okta_user)

    return user_profile


def create_user_command(client, args, mapper_out, is_command_enabled, is_update_user_enabled, is_enable_enabled):
    user_profile = IAMUserProfile(user_profile=args.get('user-profile'), mapper=mapper_out,
                                  incident_type=IAMUserProfile.CREATE_INCIDENT_TYPE)
    if not is_command_enabled:
        user_profile.set_result(action=IAMActions.CREATE_USER,
                                skip=True,
                                skip_reason='Command is disabled.')
    else:
        try:
            iam_attr, iam_attr_value = user_profile.get_first_available_iam_user_attr(GET_USER_ATTRIBUTES)
            okta_user = client.get_user(iam_attr, iam_attr_value)
            if okta_user:
                # if user exists, update its data
                return update_user_command(client, args, mapper_out, is_update_user_enabled, is_enable_enabled,
                                           is_create_user_enabled=False, create_if_not_exists=False)
            else:
                okta_profile = user_profile.map_object(mapper_out, incident_type=IAMUserProfile.CREATE_INCIDENT_TYPE)
                created_user = client.create_user(okta_profile)
                client.activate_user(created_user.get('id'))
                user_profile.set_result(
                    action=IAMActions.CREATE_USER,
                    success=True,
                    active=created_user.get('status') != DEPROVISIONED_STATUS,
                    iden=created_user.get('id'),
                    email=created_user.get('profile', {}).get('email'),
                    username=created_user.get('profile', {}).get('login'),
                    details=created_user
                )

        except Exception as e:
            handle_exception(user_profile, e, IAMActions.CREATE_USER)

    return user_profile


def update_user_command(client, args, mapper_out, is_command_enabled, is_enable_enabled,
                        is_create_user_enabled, create_if_not_exists):
    user_profile = IAMUserProfile(user_profile=args.get('user-profile'), mapper=mapper_out,
                                  incident_type=IAMUserProfile.UPDATE_INCIDENT_TYPE)
    allow_enable = args.get('allow-enable') == 'true'
    if not is_command_enabled:
        user_profile.set_result(action=IAMActions.UPDATE_USER,
                                skip=True,
                                skip_reason='Command is disabled.')
    else:
        try:
            iam_attr, iam_attr_value = user_profile.get_first_available_iam_user_attr(GET_USER_ATTRIBUTES,
                                                                                      use_old_user_data=True)
            okta_user = client.get_user(iam_attr, iam_attr_value)
            if okta_user:
                user_id = okta_user.get('id')

                if allow_enable and is_enable_enabled and okta_user.get('status') == DEPROVISIONED_STATUS:
                    client.activate_user(user_id)
                    user_profile.set_result(
                        action=IAMActions.ENABLE_USER,
                        success=True,
                        active=True,
                        iden=okta_user.get('id'),
                        email=okta_user.get('profile', {}).get('email'),
                        username=okta_user.get('profile', {}).get('login'),
                        details=okta_user
                    )
                else:
                    okta_profile = user_profile.map_object(mapper_out,
                                                           incident_type=IAMUserProfile.UPDATE_INCIDENT_TYPE)
                    updated_user = client.update_user(user_id, okta_profile)
                    user_profile.set_result(
                        action=IAMActions.UPDATE_USER,
                        success=True,
                        active=okta_user.get('status') != DEPROVISIONED_STATUS,
                        iden=updated_user.get('id'),
                        email=updated_user.get('profile', {}).get('email'),
                        username=updated_user.get('profile', {}).get('login'),
                        details=updated_user
                    )
            else:
                if create_if_not_exists:
                    return create_user_command(client, args, mapper_out, is_create_user_enabled, False, False)
                else:
                    _, error_message = IAMErrors.USER_DOES_NOT_EXIST
                    user_profile.set_result(action=IAMActions.UPDATE_USER,
                                            skip=True,
                                            skip_reason=error_message)

        except Exception as e:
            handle_exception(user_profile, e, IAMActions.UPDATE_USER)

    return user_profile


def get_app_user_assignment_command(client, args):
    user_id = args.get('user_id')
    application_id = args.get('application_id')

    res = client.get_app_user_assignment(application_id, user_id)
    raw_response = res.json()

    is_user_assigned_to_app = res.status_code == 200

    outputs = {
        'UserID': user_id,
        'AppID': application_id,
        'IsAssigned': is_user_assigned_to_app
    }

    readable_output = tableToMarkdown('App User Assignment', outputs,
                                      headers=['UserID', 'AppID', 'IsAssigned'],
                                      headerTransform=pascalToSpace)

    if is_user_assigned_to_app:
        outputs['ProfileInApp'] = raw_response.get('profile')
        profile_readable = tableToMarkdown('Profile in App', raw_response.get('profile'), removeNull=True)
        readable_output += f'\n{profile_readable}'

    return CommandResults(
        outputs=outputs,
        outputs_prefix='Okta.AppUserAssignment',
        outputs_key_field=['UserID', 'AppID'],
        readable_output=readable_output,
        raw_response=raw_response
    )


def list_apps_command(client, args):
    query = args.get('query')
    page = int(args.get('page'))
    limit = min(int(args.get('limit')), 200)

    applications = client.list_apps(query, page, limit)

    outputs = []

    for app in applications:
        outputs.append({
            'ID': app.get('id'),
            'Name': app.get('name'),
            'Label': app.get('label'),
            'Logo': f"![]({app.get('_links', {}).get('logo', [{}])[0].get('href')})"
        })

    title = 'Okta Applications'

    if applications:
        from_idx = page * limit + 1
        to_idx = from_idx + len(applications) - 1
        title += f' ({from_idx} - {to_idx})'

    return CommandResults(
        outputs=outputs,
        outputs_prefix='Okta.Application',
        outputs_key_field='ID',
        readable_output=tableToMarkdown(title, outputs, headers=['ID', 'Name', 'Label', 'Logo'])
    )


def list_user_apps_command(client, args):
    user_id = args.get('user_id')
    applications = client.list_user_apps(user_id)
    outputs = []

    for app in applications:
        outputs.append({
            'ID': app.get('id'),
            'Name': app.get('name'),
            'Label': app.get('label'),
            'Status': app.get('status')
        })

    title = 'Okta User Applications'
    return CommandResults(
        outputs=outputs,
        outputs_prefix='Okta.Application',
        outputs_key_field='ID',
        readable_output=tableToMarkdown(title, outputs, headers=['ID', 'Name', 'Label', 'Status'])
    )


def get_configuration(context):
    iam_configuration = context.get('IAMConfiguration', [])

    return CommandResults(
        outputs=iam_configuration,
        outputs_prefix='Okta.IAMConfiguration',
        outputs_key_field='ApplicationID',
        readable_output=tableToMarkdown('Okta IAM Configuration', iam_configuration)
    )


def set_configuration(args):
    iam_configuration = json.loads(args.get('configuration'))
    context = {'IAMConfiguration': iam_configuration}
    return context


def fetch_incidents(client, last_run, first_fetch_str, fetch_limit, query_filter=None,
                    auto_generate_filter=False, context=None):
    """ If no events were saved from last run, returns new events from Okta's /log API. Otherwise,
    returns the events from last run. In both cases, no more than `fetch_limit` incidents will be returned,
    and the rest of them will be saved for next run.

        Args:
            client: (BaseClient) Okta client.
            last_run: (dict) The "last run" object that was set on the previous run.
            first_fetch_str: (str) First fetch time parameter (e.g. "1 day", "2 months", etc).
            fetch_limit: (int) Maximum number of incidents to return.
            query_filter: (str) Logs API query filter.
            auto_generate_filter: (bool) Whether or not to automatically generate the query filter.
            context: (dict) Integration Context object.
        Returns:
            incidents: (dict) Incidents/events that will be created in Cortex XSOAR
            next_run: (dict) The "last run" object for the next run.
    """

    incidents = last_run.get('incidents', [])
    last_run_full_url = last_run.get('last_run_full_url')

    first_fetch_date = dateparser.parse(first_fetch_str)
    assert first_fetch_date is not None, f'could not parse {first_fetch_str}'
    first_fetch = first_fetch_date.strftime(DATE_FORMAT)
    last_run_time = last_run.get('last_run_time', first_fetch)  # if last_run_time is undefined, use first_fetch
    time_now = datetime.now().strftime(DATE_FORMAT)

    demisto.debug(f'Okta: Fetching logs from {last_run_time} to {time_now}.')
    if not incidents:
        email_to_user_profile = get_all_user_profiles()

        log_events, last_run_full_url = client.get_logs(last_run_full_url, last_run_time, time_now,
                                                        query_filter, auto_generate_filter, context)
        for entry in log_events:
            if not should_drop_event(entry, email_to_user_profile):
                add_user_profile_data_to_entry(entry, email_to_user_profile)
                incident = {'rawJSON': json.dumps(entry)}
                incidents.append(incident)

    next_run = {
        'incidents': incidents[fetch_limit:],
        'last_run_time': time_now,
        'last_run_full_url': last_run_full_url
    }

    return incidents[:fetch_limit], next_run


class OutputContext:
    """
        Class to build a generic output and context.
    """

    def __init__(self, success=None, active=None, id=None, username=None, email=None, errorCode=None,
                 errorMessage=None, details=None, displayName=None, members=None):
        self.instanceName = demisto.callingContext['context']['IntegrationInstance']
        self.brand = demisto.callingContext['context']['IntegrationBrand']
        self.command = demisto.command().replace('-', '_').title().replace('_', '')
        self.success = success
        self.active = active
        self.id = id
        self.username = username
        self.email = email
        self.errorCode = errorCode
        self.errorMessage = errorMessage
        self.details = details
        self.displayName = displayName  # Used in group
        self.members = members  # Used in group
        self.data = {
            "brand": self.brand,
            "instanceName": self.instanceName,
            "success": success,
            "active": active,
            "id": id,
            "username": username,
            "email": email,
            "errorCode": errorCode,
            "errorMessage": errorMessage,
            "details": details,
            "displayName": displayName,
            "members": members
        }
        # Remoove empty values
        self.data = {
            k: v
            for k, v in self.data.items()
            if v is not None
        }


def get_group_command(client, args):
    scim = safe_load_json(args.get('scim'))
    group_id = scim.get('id')
    group_name = scim.get('displayName')

    if not (group_id or group_name):
        return_error("You must supply either 'id' or 'displayName' in the scim data")

    group_search_result = None
    if not group_id:
        res = client.search_group(group_name)
        res_json = res.json()

        if res.status_code == 200:
            if len(res_json) < 1:
                generic_iam_context = OutputContext(success=False, displayName=group_name, errorCode=404,
                                                    errorMessage="Group Not Found", details=res_json)
            else:
                generic_iam_context = OutputContext()
                group_search_result = res_json
        else:
            generic_iam_context = OutputContext(success=False, displayName=group_name, id=group_id,
                                                errorCode=res_json.get('errorCode'),
                                                errorMessage=res_json.get('errorSummary'),
                                                details=res_json)

        if not group_search_result:
            return CommandResults(
                raw_response=generic_iam_context.data,
                outputs_prefix=generic_iam_context.command,
                outputs_key_field='id',
                outputs=generic_iam_context.data,
                readable_output=tableToMarkdown('Okta Get Group:', generic_iam_context.data, removeNull=True)
            )

    if group_search_result and len(group_search_result) > 1:
        generic_iam_context_data_list = []

        for group in group_search_result:
            group_name = group.get('profile', {}).get('name')
            generic_iam_context = OutputContext(success=True, id=group.get('id'), displayName=group_name)
            generic_iam_context_data_list.append(generic_iam_context.data)

        return CommandResults(
            raw_response=generic_iam_context_data_list,
            outputs_prefix=generic_iam_context.command,
            outputs_key_field='id',
            outputs=generic_iam_context_data_list,
            readable_output=tableToMarkdown('Okta Get Group:', generic_iam_context_data_list, removeNull=True)
        )
    elif not group_id and isinstance(group_search_result, list):
        group_id = group_search_result[0].get('id')

    res = client.get_group_by_id(group_id)
    res_json = res.json()
    if res.status_code == 200:
        group_member_profiles = []
        include_members = args.get('includeMembers')
        if include_members.lower() == 'true':
            group_members = client.get_group_members(group_id)
            for member in group_members:
                if member.get('status') != DEPROVISIONED_STATUS:
                    profile = member.get('profile', {})
                    group_member_profile = {
                        "value": member.get('id'),
                        "display": profile.get('login')
                    }
                    group_member_profiles.append(group_member_profile)
        generic_iam_context = OutputContext(success=True, id=res_json.get('id'),
                                            displayName=res_json.get('profile', {}).get('name'),
                                            members=group_member_profiles)
    elif res.status_code == 404:
        generic_iam_context = OutputContext(success=False, displayName=group_name, id=group_id, errorCode=404,
                                            errorMessage="Group Not Found", details=res_json)
    else:
        generic_iam_context = OutputContext(success=False, displayName=group_name, id=group_id,
                                            errorCode=res_json.get('errorCode'),
                                            errorMessage=res_json.get('errorSummary'),
                                            details=res_json)

    return CommandResults(
        raw_response=generic_iam_context.data,
        outputs_prefix=generic_iam_context.command,
        outputs_key_field='id',
        outputs=generic_iam_context.data,
        readable_output=tableToMarkdown('Okta Get Group:', generic_iam_context.data, removeNull=True)
    )


def get_logs_command(client, args):
    filter = args.get('filter')
    since = args.get('since')
    until = args.get('until')
    limit = args.get('limit')
    log_events, _ = client.get_logs(query_filter=filter, last_run_time=since, time_now=until, limit=limit)

    if not log_events:
        return CommandResults(readable_output='No logs found.', outputs={}, raw_response=log_events)

    return CommandResults(
        raw_response=log_events,
        outputs_prefix='Okta.Logs.Events',
        outputs_key_field='uuid',
        outputs=log_events,
        readable_output=tableToMarkdown('Okta Log Events:', log_events)
    )


def main():
    user_profile = None
    params = demisto.params()
    base_url = urljoin(params['url'].strip('/'), '/api/v1/')
    token = params.get('credentials', {}).get('password', '') or params.get('apitoken', '')

    if not token:
        raise ValueError('Missing API token.')

    mapper_in = params.get('mapper-in')
    mapper_out = params.get('mapper-out')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    command = demisto.command()
    args = demisto.args()

    is_create_enabled = params.get("create-user-enabled")
    is_enable_enabled = params.get("enable-user-enabled")
    is_disable_enabled = params.get("disable-user-enabled")
    is_update_enabled = demisto.params().get("update-user-enabled")
    create_if_not_exists = demisto.params().get("create-if-not-exists")

    is_fetch = params.get('isFetch')
    first_fetch_str = params.get('first_fetch')
    fetch_limit = int(params.get('max_fetch', 1))
    auto_generate_query_filter = params.get('auto_generate_query_filter')
    fetch_query_filter = params.get('fetch_query_filter')
    context = demisto.getIntegrationContext()

    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': f'SSWS {token}'
    }

    client = Client(
        base_url=base_url,
        verify=verify_certificate,
        proxy=proxy,
        headers=headers,
        ok_codes=(200,)
    )

    demisto.debug(f'Command being called is {command}')

    if command == 'iam-get-user':
        user_profile = get_user_command(client, args, mapper_in, mapper_out)

    elif command == 'iam-create-user':
        user_profile = create_user_command(client, args, mapper_out, is_create_enabled,
                                           is_update_enabled, is_enable_enabled)

    elif command == 'iam-update-user':
        user_profile = update_user_command(client, args, mapper_out, is_update_enabled, is_enable_enabled,
                                           is_create_enabled, create_if_not_exists)

    elif command == 'iam-disable-user':
        user_profile = disable_user_command(client, args, is_disable_enabled, mapper_out)

    if user_profile:
        return_results(user_profile)

    try:
        if command == 'test-module':
            test_module(client, is_fetch, fetch_query_filter, auto_generate_query_filter, context, first_fetch_str)

        elif command == 'get-mapping-fields':
            return_results(get_mapping_fields_command(client))

        elif command == 'okta-get-app-user-assignment':
            return_results(get_app_user_assignment_command(client, args))

        elif command == 'okta-iam-list-applications':
            return_results(list_apps_command(client, args))

        elif command == 'okta-iam-list-user-applications':
            return_results(list_user_apps_command(client, args))

        elif command == 'okta-iam-get-configuration':
            return_results(get_configuration(context))

        elif command == 'okta-iam-set-configuration':
            context = set_configuration(args)
            demisto.setIntegrationContext(context)

        elif command == 'iam-get-group':
            return_results(get_group_command(client, args))

        elif command == 'okta-get-logs':
            return_results(get_logs_command(client, args))

        elif command == 'fetch-incidents':
            last_run = demisto.getLastRun()
            context = demisto.getIntegrationContext()
            incidents, next_run = fetch_incidents(client, last_run, first_fetch_str, fetch_limit,
                                                  fetch_query_filter, auto_generate_query_filter, context)
            demisto.incidents(incidents)
            demisto.setLastRun(next_run)

    except Exception as e:
        # For any other integration command exception, return an error
        return_error(f'Failed to execute {command} command. Error: {str(e)}')


from IAMApiModule import *  # noqa: E402

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
