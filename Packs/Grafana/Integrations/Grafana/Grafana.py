from pytz import utc

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

HEADERS = {
    'Accept': 'application/json',
    'Content-Type': 'application/json'
}

# In the documentation, the state 'all' is written as 'ALL'. As the latter doesn't work, we use 'all''.
ALERT_STATES = {'all', 'no_data', 'paused', 'alerting', 'ok', 'pending', 'unknown'}

MAX_INCIDENTS_TO_FETCH = 200

FETCH_DEFAULT_TIME = '3 days'

''' CLIENT CLASS '''


class Client(BaseClient):
    def __init__(self, server_url, verify=True, proxy=False, headers=None, auth=None):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy, headers=headers, auth=auth)

    def alerts_list_request(self, dashboard_id: Optional[List[str]] = None, panel_id: str = None, query: str = None,
                            state: List[str] = None, limit: str = None, folder_id: List[str] = None,
                            dashboard_query: str = None, dashboard_tag: List[str] = None):
        # query works this way- we can get it with parenthesis or without, it adds to it
        params = assign_params(dashboardId=dashboard_id, panelId=panel_id, query=query, state=state, limit=limit,
                               folderId=folder_id, dashboardQuery=dashboard_query, dashboardTag=dashboard_tag)
        response = self._http_request('GET', 'api/alerts', params=params, headers=self._headers)
        response = self._concatenate_urls(response)
        return response

    def alert_pause_request(self, alert_id: str, paused: bool):
        data = {"paused": paused}

        response = self._http_request('POST', f'api/alerts/{alert_id}/pause', json_data=data, headers=self._headers)

        return response

    def alert_get_by_id_request(self, alert_id: str):
        response = self._http_request('GET', f'api/alerts/{alert_id}', headers=self._headers)

        return response

    def users_search_request(self, page_size: str = None, page_number: str = None, query: str = None):
        params = assign_params(perpage=page_size, page=page_number, query=query)

        response = self._http_request('GET', 'api/users', params=params, headers=self._headers)
        response = self._concatenate_urls(response, 'avatarUrl')

        return response

    def user_get_by_id_request(self, user_id: str):
        response = self._http_request('GET', f'api/users/{user_id}', headers=self._headers)
        response = self._concatenate_url(response, 'avatarUrl')

        return response

    def users_teams_request(self, user_id: str):
        response = self._http_request('GET', f'api/users/{user_id}/teams', headers=self._headers)
        response = self._concatenate_urls(response, 'avatarUrl')

        return response

    def users_organization_request(self, user_id: str):
        response = self._http_request('GET', f'api/users/{user_id}/orgs', headers=self._headers)

        return response

    def user_update_request(self, user_id: str, email: str = None, name: str = None, login: str = None,
                            theme: str = None):
        data = {"email": email, "login": login, "name": name, "theme": theme}

        response = self._http_request('PUT', f'api/users/{user_id}', json_data=data, headers=self._headers)

        return response

    def annotation_create_request(self, text: str, dashboard_id: int = None, panel_id: int = None,
                                  time_start: int = None, time_end: int = None, tags: List[str] = None):
        data = {"dashboardId": dashboard_id, "panelId": panel_id,
                "tags": tags, "text": text, "time": time_start, "timeEnd": time_end}

        response = self._http_request('POST', 'api/annotations', json_data=data, headers=self._headers)

        return response

    def teams_search_request(self, page_size: str = None, page_number: str = None, query: str = None, name: str = None):
        params = assign_params(perpage=page_size, page=page_number, query=query, name=name)

        response = self._http_request('GET', 'api/teams/search', params=params, headers=self._headers)
        response = self._concatenate_urls(response['teams'], 'avatarUrl')

        return response

    def team_get_by_id_request(self, team_id: str):
        response = self._http_request('GET', f'api/teams/{team_id}', headers=self._headers)
        response = self._concatenate_url(response, 'avatarUrl')

        return response

    def team_members_request(self, team_id: str):
        response = self._http_request('GET', f'api/teams/{team_id}/members', headers=self._headers)
        response = self._concatenate_urls(response, 'avatarUrl')

        return response

    def user_add_to_team_request(self, team_id: str, user_id: str):
        data = {"userId": int(user_id)}

        # 400 - 'User is already added to this team' might be raised - which isn't a real error
        response = self._http_request('POST', f'api/teams/{team_id}/members', json_data=data, headers=self._headers,
                                      ok_codes=(200, 400))

        return response

    def user_remove_from_team_request(self, team_id: str, user_id: str):
        response = self._http_request('DELETE', f'api/teams/{team_id}/members/{user_id}', headers=self._headers)

        return response

    def team_add_request(self, name: str, email: str = None, org_id: str = None):
        data = {"email": email, "name": name, "orgId": org_id}

        response = self._http_request('POST', 'api/teams', json_data=data, headers=self._headers)

        return response

    def team_delete_request(self, team_id: str):
        response = self._http_request('DELETE', f'api/teams/{team_id}', headers=self._headers)

        return response

    def org_create_request(self, name: str):
        data = {"name": name}

        response = self._http_request('POST', 'api/orgs', json_data=data, headers=self._headers)

        return response

    def org_list_request(self, page_size: str = None, page_number: str = None):
        params = assign_params(perpage=page_size, page=page_number)

        response = self._http_request('GET', 'api/orgs', params=params, headers=self._headers)

        return response

    def org_get_by_name_request(self, name: str):
        response = self._http_request('GET', f'api/orgs/name/{name}', headers=self._headers)

        return response

    def org_get_by_id_request(self, org_id: str = None):
        response = self._http_request('GET', f'api/orgs/{org_id}', headers=self._headers)

        return response

    def dashboards_search_request(self, query: str = None, tag: List[str] = None, type_: str = None,
                                  dashboard_ids: List[str] = None, folder_ids: List[str] = None, starred: str = None,
                                  limit: str = None, page_number: str = None):
        params = assign_params(query=query, tag=tag, type=type_, dashboardIds=dashboard_ids,
                               folderIds=folder_ids, starred=starred, limit=limit, page=page_number)

        response = self._http_request('GET', 'api/search', params=params, headers=self._headers)
        response = self._concatenate_urls(response)

        return response

    def _concatenate_urls(self, responses: List[Dict[str, Any]], url_field: str = 'url'):
        """
        Concatenates a url suffix with the base url for the places where only a suffix is returned.
        Updates the list of dicts given, and returns it.
        """
        for response in responses:
            self._concatenate_url(response, url_field)
        return responses

    def _concatenate_url(self, response: Dict[str, Any], url_field: str = 'url'):
        """
        Concatenates a url suffix with the base url for the places where only a suffix is returned, so urls we display will be
        clickable and lead to a real place.
        Updates the dict given, and returns it.
        """
        if url_field in response:
            url = urljoin(self._base_url, response[url_field])
            response[url_field] = url
        return response


''' HELPER FUNCTIONS '''


def set_time_to_epoch_millisecond(time_to_set: Optional[str] = None):
    """
    For annotation creation, sets the time to epoch numbers in millisecond resolution - if it was filled.
    """
    if time_to_set:
        return int(dateparser.parse(time_to_set).timestamp()) * 1000


def change_key(response: dict, prev_key: str, new_key: str):
    """
    This function changes a key in response, so the values could be aggregated with other functions.
    """
    if prev_key in response:
        response[new_key] = response.pop(prev_key)
    demisto.debug(f'changing key "{prev_key}" in response to "{new_key}", edited response is: {response}')
    return response


def keys_to_lowercase(response: dict):
    """
    Lowers firsts letter of all keys in the dictionary given and returns the new dictionary.
    """
    demisto.debug(f'lowering keys for response: {response}')
    return dict((decapitalize(key), value) for (key, value) in response.items())


def decapitalize(s: str):
    """
    Decapitalizes a given string.
    """
    if not s:
        return s
    demisto.debug(f'de-capitalizing key: {s}')
    return s[0].lower() + s[1:]


def paging_heading(page_number: str = None, page_size: str = None):
    if page_number or page_size:
        return 'Showing' + (f' {page_size}' if page_size else '') + ' results' +\
               (f' from page {page_number}' if page_number else '') + ':\n'
    return ''


def set_state(states: str = ''):
    states = argToList(states)
    for state in states:
        if state not in ALERT_STATES:
            raise DemistoException("State must be of: all, no_data, paused, alerting, ok, pending, unknown.")
    # if all is not the first state given, Grafana ignores it and returns only other states given
    if 'all' in states:
        states = []
    return states


def calculate_fetch_start_time(last_fetch: str = None, first_fetch: str = FETCH_DEFAULT_TIME):
    first_fetch_datetime = dateparser.parse(first_fetch).replace(tzinfo=utc, microsecond=0)
    if last_fetch is None:
        return first_fetch_datetime

    last_fetch = dateparser.parse(last_fetch).replace(tzinfo=utc, microsecond=0)
    return max(last_fetch, first_fetch_datetime)


def filter_alerts_by_time(alerts: List[Dict[str, Any]], last_fetch: datetime):
    # ignoring microsecond because date_to_timestamp doesn't know how to handle it
    return [alert for alert in alerts if dateparser.parse(alert['newStateDate']).replace(tzinfo=utc, microsecond=0) >= last_fetch]


def filter_alerts_by_id(alerts: List[Dict[str, Any]], last_fetch: datetime, last_id_fetched: int):
    # only for alerts with the same newStateDate as last_fetch
    return [alert for alert in alerts
            if dateparser.parse(alert['newStateDate']).replace(tzinfo=utc, microsecond=0) != last_fetch
            or alert['id'] > last_id_fetched]


def reduce_incidents_to_limit(alerts: List[Dict[str, Any]], limit: int, last_fetch: datetime, last_id_fetched: int):
    incidents_count = min(limit, len(alerts))
    # limit can't be 0 or less, but there could be no alerts at the wanted time
    if incidents_count > 0:
        alerts = alerts[:limit]
        last_fetched_alert = alerts[incidents_count - 1]
        last_fetch = dateparser.parse(last_fetched_alert['newStateDate']).replace(tzinfo=utc, microsecond=0)
        last_id_fetched = last_fetched_alert['id']
    return last_fetch, last_id_fetched, alerts


def parse_alerts(alerts: List[Dict[str, Any]], limit: int, last_fetch: datetime, last_id_fetched: int):
    alerts = filter_alerts_by_time(alerts, last_fetch)
    alerts = filter_alerts_by_id(alerts, last_fetch, last_id_fetched)

    # sorting alerts by date and then by id
    alerts.sort(key=lambda alert: (dateparser.parse(alert['newStateDate']).replace(tzinfo=utc), alert['id']))

    last_fetch, last_id_fetched, alerts = reduce_incidents_to_limit(alerts, limit, last_fetch, last_id_fetched)

    incidents: List[Dict[str, Any]] = [alert_to_incident(alert) for alert in alerts]
    return last_fetch, last_id_fetched, incidents


def alert_to_incident(alert: Dict[str, Any]):
    alert['type'] = 'Grafana Alert'
    incident = {
        'name': alert['name'],
        'occurred': alert['newStateDate'],
        'rawJSON': json.dumps(alert),
        'type': alert['type']
    }
    return incident


''' COMMAND FUNCTIONS '''


def alerts_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    dashboard_id = argToList(args.get('dashboard_id', ''))

    panel_id = args.get('panel_id')
    query = args.get('name')
    state = set_state(args.get('state', ''))
    limit = args.get('limit')
    folder_id = argToList(args.get('folder_id', ''))
    dashboard_query = args.get('dashboard_name')
    dashboard_tag = argToList(args.get('dashboard_tag', ''))

    responses = client.alerts_list_request(dashboard_id, panel_id, query, state,
                                           limit, folder_id, dashboard_query, dashboard_tag)

    for response in responses:
        change_key(response, 'dashboardSlug', 'dashboardName')

    headers = ['id', 'name', 'state', 'newStateDate', 'panelId', 'dashboardId', 'dashboardUid', 'dashboardName', 'url']
    command_results = CommandResults(
        outputs_prefix='Grafana.Alert',
        outputs_key_field='id',
        outputs=responses,
        raw_response=responses,
        readable_output=tableToMarkdown('Existing Alerts:', responses, headers=headers, removeNull=True,
                                        headerTransform=pascalToSpace, url_keys=['url'])
    )

    return command_results


def alert_pause_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    alert_id = str(args.get('alert_id'))

    response = client.alert_pause_request(alert_id, True)
    response = change_key(response, 'alertId', 'id')

    command_results = CommandResults(
        outputs_prefix='Grafana.Alert',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown(f'Paused Alert {alert_id}:', response, removeNull=True, headerTransform=pascalToSpace)
    )

    return command_results


def alert_unpause_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    alert_id = str(args.get('alert_id'))

    response = client.alert_pause_request(alert_id, False)
    response = change_key(response, 'alertId', 'id')

    command_results = CommandResults(
        outputs_prefix='Grafana.Alert',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown(f'Un-paused Alert {alert_id}:', response, removeNull=True, headerTransform=pascalToSpace)
    )

    return command_results


def alert_get_by_id_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    alert_id = str(args.get('alert_id'))

    response = client.alert_get_by_id_request(alert_id)
    # output returns keys capitalized rather then with first lower case letter (as stated and should be)
    response = keys_to_lowercase(response)

    headers = ['id', 'version', 'orgId', 'dashboardId', 'panelId', 'name', 'message', 'severity', 'state', 'newStateDate',
               'stateChanges', 'handler', 'silenced', 'frequency', 'for', 'created', 'updated']
    command_results = CommandResults(
        outputs_prefix='Grafana.Alert',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown(f'Alert {alert_id} Results:', response, headers=headers, removeNull=True,
                                        headerTransform=pascalToSpace)
    )

    return command_results


def users_search_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_size = args.get('page_size')
    page_number = args.get('page_number')
    query = args.get('query')

    response = client.users_search_request(page_size, page_number, query)
    headers = ['id', 'email', 'name', 'login', 'isAdmin', 'isDisabled', 'avatarUrl', 'lastSeenAt', 'lastSeenAtAge', 'authLabels']

    command_results = CommandResults(
        outputs_prefix='Grafana.User',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
        readable_output=paging_heading(page_number, page_size)
        + tableToMarkdown('Existing Users:', response, headers=headers, removeNull=True,
                          headerTransform=pascalToSpace, url_keys=['avatarUrl'])
    )

    return command_results


def user_get_by_id_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    user_id = str(args.get('user_id'))

    response = client.user_get_by_id_request(user_id)
    headers = ['id', 'email', 'name', 'login', 'theme', 'orgId', 'isGrafanaAdmin', 'isDisabled', 'isExternal', 'updatedAt',
               'createdAt', 'avatarUrl', 'authLabels']

    command_results = CommandResults(
        outputs_prefix='Grafana.User',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown(f'User {user_id} Results:', response, headers=headers, removeNull=True,
                                        headerTransform=pascalToSpace, url_keys=['avatarUrl'])
    )

    return command_results


def users_teams_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    user_id = str(args.get('user_id'))

    response = client.users_teams_request(user_id)
    output = {'id': user_id, 'teams': response}
    headers = ['id', 'orgId', 'name', 'email', 'avatarUrl', 'memberCount', 'permission']

    command_results = CommandResults(
        outputs_prefix='Grafana.User',
        outputs_key_field='id',
        outputs=output,
        raw_response=response,
        readable_output=tableToMarkdown(f'Teams For User {user_id}:', response, headers=headers, removeNull=True,
                                        headerTransform=pascalToSpace, url_keys=['avatarUrl'])
    )

    return command_results


def users_organization_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    user_id = str(args.get('user_id'))

    response = client.users_organization_request(user_id)
    output = {'id': user_id, 'orgs': response}

    command_results = CommandResults(
        outputs_prefix='Grafana.User',
        outputs_key_field='id',
        outputs=output,
        raw_response=response,
        readable_output=tableToMarkdown(f'Organizations For User {user_id}:', response, removeNull=True,
                                        headerTransform=pascalToSpace)
    )

    return command_results


def user_update_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    user_id = str(args.get('user_id'))
    email = args.get('email')
    name = args.get('name')
    login = args.get('login')
    theme = args.get('theme')

    # login\email is required
    if not login and not email:
        raise DemistoException("Login or email must be specified.")

    response = client.user_update_request(user_id, email, name, login, theme)
    command_results = CommandResults(
        readable_output=tableToMarkdown(f'Successfully Updated User {user_id}:', response, removeNull=True,
                                        headerTransform=pascalToSpace))

    return command_results


def annotation_create_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    dashboard_id = arg_to_number(args.get('dashboard_id'))
    panel_id = arg_to_number(args.get('panel_id'))

    time_start = set_time_to_epoch_millisecond(args.get('time'))
    time_end = set_time_to_epoch_millisecond(args.get('time_end'))

    tags = argToList(args.get('tags', ''))
    text = str(args.get('text'))

    response = client.annotation_create_request(text, dashboard_id, panel_id, time_start, time_end, tags)

    command_results = CommandResults(
        outputs_prefix='Grafana.Annotation',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown(f'Successfully Created Annotation {response["id"]}:', response, removeNull=True,
                                        headerTransform=pascalToSpace)
    )

    return command_results


def teams_search_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_size = args.get('page_size')
    page_number = args.get('page_number')
    query = args.get('query')
    name = args.get('name')

    response = client.teams_search_request(page_size, page_number, query, name)
    headers = ['id', 'orgId', 'name', 'email', 'avatarUrl', 'memberCount', 'permission']

    command_results = CommandResults(
        outputs_prefix='Grafana.Team',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
        readable_output=paging_heading(page_number, page_size)
        + tableToMarkdown('Teams Search Results:', response, headers=headers, removeNull=True,
                          headerTransform=pascalToSpace, url_keys=['avatarUrl'])
    )

    return command_results


def team_get_by_id_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    team_id = str(args.get('team_id'))

    response = client.team_get_by_id_request(team_id)
    headers = ['id', 'orgId', 'name', 'email', 'avatarUrl', 'memberCount', 'permission']
    command_results = CommandResults(
        outputs_prefix='Grafana.Team',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown(f'Team {team_id} Results:', response, headers=headers, removeNull=True,
                                        headerTransform=pascalToSpace, url_keys=['avatarUrl'])
    )

    return command_results


def team_members_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    team_id = str(args.get('team_id'))

    response = client.team_members_request(team_id)
    headers = ['orgId', 'teamId', 'userId', 'auth_module', 'email', 'name', 'login', 'avatarUrl', 'labels', 'permission']
    output = {'id': team_id, 'members': response}

    command_results = CommandResults(
        outputs_prefix='Grafana.Team',
        outputs_key_field='id',
        outputs=output,
        raw_response=response,
        readable_output=tableToMarkdown(f'Team {team_id} Members:', response, headers=headers, removeNull=True,
                                        headerTransform=pascalToSpace, url_keys=['avatarUrl'])
    )

    return command_results


def user_add_to_team_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    team_id = str(args.get('team_id'))
    user_id = str(args.get('user_id'))

    response = client.user_add_to_team_request(team_id, user_id)
    command_results = CommandResults(
        readable_output=tableToMarkdown(f'Successfully Added User {user_id} to Team {team_id}:', response, removeNull=True,
                                        headerTransform=pascalToSpace)
    )

    return command_results


def user_remove_from_team_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    team_id = str(args.get('team_id'))
    user_id = str(args.get('user_id'))

    response = client.user_remove_from_team_request(team_id, user_id)
    command_results = CommandResults(
        readable_output=tableToMarkdown(f'Successfully Removed User {user_id} from Team {team_id}:', response, removeNull=True,
                                        headerTransform=pascalToSpace))

    return command_results


def team_add_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    name = str(args.get('name'))
    email = args.get('email')
    org_id = args.get('org_id')

    response = client.team_add_request(name, email, org_id)
    output = change_key(dict(response), 'teamId', 'id')

    command_results = CommandResults(
        outputs_prefix='Grafana.Team',
        outputs_key_field='id',
        outputs=output,
        raw_response=response,
        readable_output=tableToMarkdown(f'Successfully Created Team {response["teamId"]}:', response, removeNull=True,
                                        headerTransform=pascalToSpace)
    )

    return command_results


def team_delete_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    team_id = str(args.get('team_id'))

    response = client.team_delete_request(team_id)
    command_results = CommandResults(
        readable_output=tableToMarkdown(f'Successfully Deleted Team {team_id}:', response, removeNull=True,
                                        headerTransform=pascalToSpace)
    )

    return command_results


def org_create_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    name = str(args.get('name'))

    response = client.org_create_request(name)
    output = change_key(dict(response), 'orgId', 'id')

    command_results = CommandResults(
        outputs_prefix='Grafana.Organization',
        outputs_key_field='id',
        outputs=output,
        raw_response=response,
        readable_output=tableToMarkdown(f'Successfully Created Organization {response["orgId"]}:', response, removeNull=True,
                                        headerTransform=pascalToSpace)
    )

    return command_results


def org_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_size = args.get('page_size')
    page_number = args.get('page_number')  # reply doesn't show this and total

    response = client.org_list_request(page_size, page_number)
    command_results = CommandResults(
        outputs_prefix='Grafana.Organization',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
        readable_output=paging_heading(page_number, page_size)
        + tableToMarkdown('Existing Organizations:', response, removeNull=True, headerTransform=pascalToSpace)
    )

    return command_results


def org_get_by_name_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    name = str(args.get('name'))

    response = client.org_get_by_name_request(name)
    headers = ['name', 'id', 'address']
    command_results = CommandResults(
        outputs_prefix='Grafana.Organization',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown(f'Organization "{name}" Results:', response, headers=headers, removeNull=True,
                                        headerTransform=pascalToSpace)
    )

    return command_results


def org_get_by_id_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    org_id = args.get('org_id')

    response = client.org_get_by_id_request(org_id)
    headers = ['id', 'name', 'address']
    command_results = CommandResults(
        outputs_prefix='Grafana.Organization',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown(f'Organization {org_id} Results:', response, headers=headers, removeNull=True,
                                        headerTransform=pascalToSpace)
    )

    return command_results


def dashboards_search_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    query = args.get('query')
    tag = argToList(args.get('tag', ''))
    type_ = args.get('type')
    dashboard_ids = argToList(args.get('dashboard_ids', ''))
    folder_ids = argToList(args.get('folder_ids', ''))
    starred = args.get('starred')
    limit = args.get('limit')
    page_number = args.get('page_number')

    response = client.dashboards_search_request(query, tag, type_, dashboard_ids, folder_ids, starred, limit, page_number)
    headers = ['id', 'uid', 'title', 'isStarred', 'tags', 'uri', 'url', 'slug', 'type']
    command_results = CommandResults(
        outputs_prefix='Grafana.Dashboard',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
        readable_output=paging_heading(page_number, limit)
        + tableToMarkdown('Existing Dashboards:', response, headers=headers, removeNull=True,
                          headerTransform=pascalToSpace, url_keys=['url'])
    )

    return command_results


def test_module(client: Client, params: dict) -> None:
    message: str = ''
    try:
        if client.users_search_request():
            message = 'ok'

        if params['isFetch']:
            max_fetch = arg_to_number(params.get('max_fetch'))
            if max_fetch is not None and (max_fetch > MAX_INCIDENTS_TO_FETCH or max_fetch <= 0):
                raise DemistoException(f'Maximum number of incidents to fetch exceeds the limit '
                                       f'(restricted to {MAX_INCIDENTS_TO_FETCH}), or is below zero.')
            client.alerts_list_request(dashboard_id=argToList(params.get('dashboard_id')), panel_id=params.get('panel_id'),
                                       query=params.get('alert_name'), state=params.get('state'))

    except DemistoException as e:
        if 'Unauthorized' in str(e):
            message = 'Authorization Error: make sure username and password are correctly set'
        else:
            raise e
    return return_results(message)


def fetch_incidents(client: Client, first_fetch: str, dashboard_id: str = None, panel_id: str = None,
                    alert_name: str = None, state: str = None, limit: Optional[int] = MAX_INCIDENTS_TO_FETCH) -> List[dict]:
    limit = limit or MAX_INCIDENTS_TO_FETCH
    last_fetch = demisto.getLastRun().get('last_fetch')
    last_id_fetched = demisto.getLastRun().get('last_id_fetched', -1)
    fetch_start_time = calculate_fetch_start_time(last_fetch, first_fetch)
    demisto.debug(f'last fetch was at: {last_fetch}, last id fetched was: {last_id_fetched}, '
                  f'time to fetch from is: {fetch_start_time}')

    alerts = client.alerts_list_request(dashboard_id=argToList(dashboard_id), panel_id=panel_id, query=alert_name,
                                        state=argToList(state))
    last_fetch, last_id_fetched, incidents = parse_alerts(alerts, limit, fetch_start_time, last_id_fetched)
    demisto.debug(f'last fetch now is: {last_fetch}, last id fetched is now: {last_id_fetched}, '
                  f'number of incidents fetched is {len(incidents)}, number of alerts got is {len(alerts)}')

    demisto.setLastRun({'last_fetch': str(date_to_timestamp(last_fetch, DATE_FORMAT)), 'last_id_fetched': last_id_fetched})
    return incidents


''' MAIN FUNCTION '''


def main():
    """main function, parses params and runs command functions
    """
    params = demisto.params()
    args = demisto.args()
    url = params['url']
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    username = params['credentials']['identifier']
    password = params['credentials']['password']
    # we chose to use only Basic authentication, even though in some requests a Bearer authentication is documented
    # and is enough, because for some other queries Basic authentication is required

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        requests.packages.urllib3.disable_warnings()
        client = Client(urljoin(url, ''), verify_certificate, proxy, headers=HEADERS, auth=(username, password))

        commands = {
            'grafana-alerts-list': alerts_list_command,
            'grafana-alert-pause': alert_pause_command,
            'grafana-alert-unpause': alert_unpause_command,
            'grafana-alert-get-by-id': alert_get_by_id_command,
            'grafana-users-search': users_search_command,
            'grafana-user-get-by-id': user_get_by_id_command,
            'grafana-user-teams-get': users_teams_command,
            'grafana-user-orgs-get': users_organization_command,
            'grafana-user-update': user_update_command,
            'grafana-annotation-create': annotation_create_command,
            'grafana-teams-search': teams_search_command,
            'grafana-team-get-by-id': team_get_by_id_command,
            'grafana-team-members-list': team_members_command,
            'grafana-user-add-to-team': user_add_to_team_command,
            'grafana-user-remove-from-team': user_remove_from_team_command,
            'grafana-team-add': team_add_command,
            'grafana-team-delete': team_delete_command,
            'grafana-org-create': org_create_command,
            'grafana-org-list': org_list_command,
            'grafana-org-get-by-name': org_get_by_name_command,
            'grafana-org-get-by-id': org_get_by_id_command,
            'grafana-dashboards-search': dashboards_search_command
        }

        if command == 'fetch-incidents':
            first_fetch = params.get('first_fetch', FETCH_DEFAULT_TIME)

            dashboard_id = params.get('dashboard_id')
            panel_id = params.get('panel_id')
            alert_name = params.get('alert_name')
            state = params.get('state')
            limit = arg_to_number(params.get('max_fetch'))

            incidents = fetch_incidents(client, first_fetch, dashboard_id, panel_id, alert_name, state, limit)
            demisto.incidents(incidents)

        elif command == 'test-module':
            test_module(client, params)
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        return_error(str(e))


''' ENTRY POINT '''

if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
