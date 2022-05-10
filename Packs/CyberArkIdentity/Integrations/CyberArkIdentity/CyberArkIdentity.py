from SiemApiModule import *

# -----------------------------------------  GLOBAL VARIABLES  -----------------------------------------
DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'
EVENT_FIELDS = [
    'AuthMethod',
    'DirectoryServiceUuid',
    'DirectoryServicePartnerName',
    'EntityName',
    'EntityType',
    'EntityUuid'
    'FromIPAddress',
    'Level',
    'ImpersonatorUuiid',
    'NewEntity',
    'NormalizedUser',
    'OldEntity',
    'RequestDeviceOS',
    'RequestHostName',
    'RequestIsMobileDevice',
    'Tenant',
    'UserGuid',
    'WhenLogged',
    'WhenOccurred',
]


# -----------------------------------------  HELPER FUNCTIONS  -----------------------------------------
def get_access_token(**kwargs: dict) -> str:
    credentials = Credentials(kwargs)
    user_name = credentials.identifier
    password = credentials.password
    url = f'{kwargs.get("url")}/oauth2/token/{kwargs.get("app_id")}'
    headers = {'Authorization': f"Basic {base64.b64encode(f'{user_name}:{password}'.encode()).decode()}"}
    data = {'grant_type': 'client_credentials', 'scope': 'siem'}

    response = requests.post(url, headers=headers, data=data, verify=not kwargs.get('insecure'))
    json_response = response.json()
    access_token = json_response.get('access_token')

    return access_token


def get_headers(access_token: str) -> dict:
    return {
        'Authorization': f'Bearer {access_token}',
        'Accept': '*/*',
        'Content-Type': 'application/json'
    }


def get_body(fetch_from: str) -> dict:
    _from = dateparser.parse(fetch_from, settings={'TIMEZONE': 'UTC'}).strftime(DATE_FORMAT)
    to = datetime.now().strftime(DATE_FORMAT)

    return {"Script": f"Select {EVENT_FIELDS} from Event where WhenOccurred >= '{_from}' and WhenOccurred <= '{to}'"}


def main():
    # Args is always stronger. Get last run even stronger
    demisto_params = demisto.params() | demisto.args() | demisto.getLastRun()
    command = demisto.command()
    demisto.debug(f'Command {command} was called!!!')

    demisto_params['headers'] = get_headers(get_access_token(**demisto_params))
    demisto_params['data'] = json.dumps(get_body(demisto_params.get('from', '3 days')))
    demisto_params['url'] = demisto.params().get('url', '') + 'RedRock/Query'

    request = Request(**demisto_params)
    client = Client(request)
    get_events = GetEvents(client)

    try:
        if command == 'test-module':
            get_events.run(1)
            demisto.results('ok')
        elif command in ('fetch-events', 'CyberArkIdentity-fetch-events'):
            events = get_events.run(demisto_params.get('max_fetch'))
            if events:
                if command == 'fetch-events':
                    send_events_to_xsiam(events, 'CyberArkIdentity', 'RedRock records')
                if command == 'CyberArkIdentity-fetch-events':
                    get_events.events_to_incidents(events)
                    CommandResults(
                        readable_output=tableToMarkdown('CyberArkIdentity RedRock records', events, removeNull=True, headerTransform=pascalToSpace),
                        outputs_prefix='JiraAudit.Records',
                        outputs_key_field='id',
                        outputs=events,
                        raw_response=events,
                    )
                    demisto.results(CommandResults)
                demisto.setLastRun({'from': events[-1].get('')})
    except Exception as e:
        return_error(str(e))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
