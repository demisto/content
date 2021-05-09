from CommonServerPython import *

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' CONSTANTS '''
INTEGRATION_NAME = 'FireEye Central Management'
INTEGRATION_COMMAND_NAME = 'fireeye-cm'
INTEGRATION_CONTEXT_NAME = 'FireEyeCM'
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

''' CLIENT CLASS '''


class Client(BaseClient):
    def __init__(self, base_url: str, username: str, password: str, verify: bool, proxy: bool):
        super().__init__(base_url=base_url, auth=(username, password), verify=verify, proxy=proxy)
        self._headers = {
            'X-FeApi-Token': self._generate_token(),
            'Accept': 'application/json',
        }

    def _generate_token(self) -> str:
        resp = self._http_request(method='POST', url_suffix='auth/login', resp_type='response')
        if resp.status_code != 200:
            raise DemistoException(f'Token request failed with status code {resp.status_code}. message: {str(resp)}')
        return resp.headers['X-FeApi-Token']

    def get_alerts_request(self, alert_id: str) -> Dict[str, str]:
        return self._http_request(method='GET', url_suffix='alerts', params={'alert_id': alert_id}, resp_type='json')

    def get_alert_details_request(self, alert_id: str) -> Dict[str, str]:
        return self._http_request(method='GET', url_suffix=f'alerts/alert/{alert_id}', resp_type='json')

    def alert_acknowledge_request(self, uuid: str) -> Dict[str, str]:
        # data here is redundant, but without it we are getting an error.
        # "Bad Request" with Invalid input. code:ALRTCONF001
        return self._http_request(method='POST', url_suffix=f'alerts/alert/{uuid}',
                                  params={'schema_compatibility': True}, data=json.dumps({"annotation": "<test>"}),
                                  resp_type='resp')

    def get_artifacts_by_uuid_request(self, uuid: str, timeout: int) -> Dict[str, str]:
        self._headers.pop('Accept')  # returns a file, hence this header is disruptive
        return self._http_request(method='GET', url_suffix=f'artifacts/{uuid}', resp_type='content', timeout=timeout)


def test_module(client: Client) -> str:
    # check get alerts for fetch purposes
    return CommandResults('ok')


def get_alerts(client: Client, args: Dict[str, Any]) -> CommandResults:
    alert_id = args.get('alert_id')

    raw_response = client.get_alerts_request(alert_id)

    alerts = raw_response.get('alert')

    headers = ['id', 'occurred', 'product', 'name', 'malicious', 'action', 'src', 'dst', 'severity', 'alertUrl']
    md_ = tableToMarkdown(name=f'{INTEGRATION_NAME} Alerts:', t=alerts, headers=headers, removeNull=True)

    return CommandResults(
        readable_output=md_,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.alerts',
        outputs_key_field='id',
        outputs=alerts,
        raw_response=raw_response
    )


def get_alert_details(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    alert_ids = argToList(args.get('alert_id'))
    command_results: List[CommandResults] = []

    headers = ['id', 'occurred', 'product', 'name', 'malicious', 'action', 'src', 'dst', 'severity', 'alertUrl']

    for alert_id in alert_ids:
        raw_response = client.get_alert_details_request(alert_id)

        alert_details = raw_response.get('alert')
        if not alert_details:
            md_ = f'Alert {alert_id} was not found.'
        else:
            md_ = tableToMarkdown(name=f'{INTEGRATION_NAME} Alerts:', t=alert_details, headers=headers, removeNull=True)

        command_results.append(CommandResults(
            readable_output=md_,
            outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.alerts',
            outputs_key_field='id',
            outputs=alert_details,
            raw_response=raw_response
        ))

    return command_results


def alert_acknowledge(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    uuids = argToList(args.get('uuid'))
    command_results: List[CommandResults] = []

    for uuid in uuids:
        try:
            client.alert_acknowledge_request(uuid)
            md_ = f'Alert {uuid} was acknowledged successfully.'
        except Exception as err:
            if 'Alert not found or cannot update' in str(err.message):
                md_ = f'Alert {uuid} was not found or cannot update. it may have been acknowledged in the past.'
            else:
                raise err

        command_results.append(CommandResults(
            readable_output=md_
        ))

    return command_results


def get_artifacts_by_uuid(client: Client, args: Dict[str, Any]):
    uuids = argToList(args.get('uuid'))
    timeout = int(args.get('timeout'))
    for uuid in uuids:
        artifact = client.get_artifacts_by_uuid_request(uuid, timeout)
        demisto.results(fileResult(f'artifacts_{uuid}.zip', data=artifact, file_type=EntryType.ENTRY_INFO_FILE))


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    username = params.get('credentials').get('identifier')
    password = params.get('credentials').get('password')
    # there is also a v1.2.0 which holds different reqs, we support only the newest API version
    base_url = urljoin(params.get('url'), '/wsapis/v2.0.0/')
    verify = not argToBoolean(params.get('insecure', 'false'))
    proxy = argToBoolean(params.get('proxy'))

    # # fetch params
    # fetch_query = params.get('fetch_query')
    # max_fetch = min('50', params.get('max_fetch', '50'))
    # first_fetch_time = params.get('fetch_time', '3 days').strip()

    command = demisto.command()
    args = demisto.args()
    LOG(f'Command being called is {command}')
    try:
        client = Client(base_url=base_url, username=username, password=password, verify=verify, proxy=proxy)
        # raise Exception(client._headers['X-FeApi-Token'])
        commands = {
            f'{INTEGRATION_COMMAND_NAME}-get-alerts': get_alerts,
            f'{INTEGRATION_COMMAND_NAME}-get-alert-details': get_alert_details,
            f'{INTEGRATION_COMMAND_NAME}-alert-acknowledge': alert_acknowledge,
            f'{INTEGRATION_COMMAND_NAME}-get-artifacts-by-uuid': get_artifacts_by_uuid,
        }
        if demisto.command() == 'test-module':
            return_results(test_module(client))
        # elif command == 'fetch-incidents':
        #     next_run, incidents = fetch_incidents(
        #         client=client,
        #         last_run=demisto.getLastRun(),
        #         fetch_query=fetch_query,
        #         first_fetch_time=first_fetch_time,
        #         max_fetch=max_fetch
        #     )
        #     demisto.setLastRun(next_run)
        #     demisto.incidents(incidents)
        elif command == f'{INTEGRATION_COMMAND_NAME}-get-artifacts-by-uuid':
            get_artifacts_by_uuid(client, args)
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')

    except Exception as err:
        return_error(str(err), err)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
