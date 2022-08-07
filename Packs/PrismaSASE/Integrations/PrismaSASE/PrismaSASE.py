import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

# CONSTANTS
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
SEARCH_LIMIT = 200


SECURITYRULE_FIELDS = {
    "name": "",
    "action": "",
    "description": "",
    "log_setting": "",
    "application": [],
    "category": [],
    "destination": [],
    "destination_hip": [],
    "profile_setting": {},
    "service": [],
    "source": [],
    "source_hip": [],
    "source_user": [],
    "tag": [],
    "from": [],
    "to": [],
    "disabled": "",
    "negate_source": "",
    "negate_destination": ""
}


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls to the Saas Security platform, and does not contain any XSOAR logic.
    Handles the token retrieval.

    :param base_url (str): Saas Security server url.
    :param client_id (str): client ID.
    :param client_secret (str): client secret.
    :param verify (bool): specifies whether to verify the SSL certificate or not.
    :param proxy (bool): specifies if to use XSOAR proxy settings.
    """

    def __init__(self, base_url: str, client_id: str, client_secret: str, oauth_url: str, verify: bool, proxy: bool, **kwargs):
        self.client_id = client_id
        self.client_secret = client_secret
        self.oauth_url = oauth_url

        super().__init__(base_url=base_url, verify=verify, proxy=proxy, **kwargs)

    @staticmethod
    def build_security_rule(args: dict):

        # This method will combine the args into a JSON formatted request body
        rule = {}
        keys = args.keys()
        for key in SECURITYRULE_FIELDS:
            if key in keys:
                if key == 'profile_setting':

                    if isinstance(args.get(key), list):
                        val = args.get(key)
                    else:
                        val = [x.strip() for x in args.get(key).split(',')]   # type: ignore

                    rule[key] = {'group': val}

                elif isinstance(SECURITYRULE_FIELDS.get(key), str):
                    rule[key] = args.get(key)   # type: ignore

                elif isinstance(SECURITYRULE_FIELDS.get(key), list):
                    if isinstance(args.get(key), list):
                        val = args.get(key)
                    else:
                        val = [x.strip() for x in args.get(key).split(';')]   # type: ignore

                    rule[key] = val   # type: ignore

        return rule

    def create_security_rule(self, rule: dict, folder: str, position: str, tsg_id: str):
        uri = '/sse/config/v1/security-rules'
        access_token = self.get_access_token(tsg_id)

        query_params = {
            'folder': encode_string_results(folder),
            'position': encode_string_results(position)
        }

        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': f"Bearer {access_token}"
        }

        return self._http_request(
            method="POST",
            url_suffix=uri,
            params=query_params,
            json_data=rule,
            headers=headers
        )

    def update_security_rule(self, rule: dict, folder: str, position: str, ruleid: str, tsg_id: str):
        uri = f'/sse/config/v1/security-rules/{ruleid}'
        access_token = self.get_access_token(tsg_id)

        query_params = {
            'folder': encode_string_results(folder),
            'position': encode_string_results(position)
        }

        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': f"Bearer {access_token}"
        }

        return self._http_request(
            method="PUT",
            url_suffix=uri,
            params=query_params,
            json_data=rule,
            headers=headers
        )

    def delete_security_rule(self, rule_id: str, tsg_id: str):
        uri = f'/sse/config/v1/security-rules/{rule_id}'
        access_token = self.get_access_token(tsg_id)
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': f"Bearer {access_token}"
        }

        return self._http_request(
            method="DELETE",
            url_suffix=uri,
            headers=headers
        )

    def list_security_rules(self, query_params: dict, tsg_id: str):
        uri = '/sse/config/v1/security-rules'

        access_token = self.get_access_token(tsg_id)

        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': f"Bearer {access_token}"
        }

        return self._http_request(
            method="GET",
            url_suffix=uri,
            params=query_params,
            headers=headers
        )

    def query_agg_monitor_api(self, tsg_id: str, uri: str, query: dict):

        query_params = {
            'agg_by': "tenant"
        }

        access_token = self.get_access_token(tsg_id)

        headers = {
            'Content-Type': 'application/json',
            'Authorization': f"Bearer {access_token}"
        }

        if query is not None:
            return self._http_request(
                method="POST",
                url_suffix=uri,
                params=query_params,
                headers=headers,
                json_data=query
            )
        else:
            return self._http_request(
                method="GET",
                url_suffix=uri,
                params=query_params,
                headers=headers
            )

    def push_candidate_config(self, devices: str, description: str, tsg_id: str):

        uri = '/sse/config/v1/config-versions/candidate:push'

        access_token = self.get_access_token(tsg_id)

        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': f"Bearer {access_token}"
        }

        body = {"folders": devices}

        if description:
            body['description'] = description

        return self._http_request(
            method="POST",
            url_suffix=uri,
            headers=headers,
            json_data=body
        )

    def get_config_jobs_by_id(self, tsg_id: str, job_id: str):

        uri = f'/sse/config/v1/jobs/{job_id}'
        access_token = self.get_access_token(tsg_id)

        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': f"Bearer {access_token}"
        }

        return self._http_request(
            method="GET",
            url_suffix=uri,
            headers=headers
        )

    def list_config_jobs(self, tsg_id: str, query_params: dict):

        uri = '/sse/config/v1/jobs'
        access_token = self.get_access_token(tsg_id)
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': f"Bearer {access_token}"
        }
        return self._http_request(
            method="GET",
            url_suffix=uri,
            params=query_params,
            headers=headers
        )

    def get_access_token(self, tsg_id: str):

        # Get existin API access token for specific TSG from integration context.
        previous_token = get_integration_context()
        tsg_access_token = f'{tsg_id}.access_token'
        tsg_expiry_time = f'{tsg_id}.expiry_time'

        '''
        If there is an existing access token, and it has not expired, set it as the access token for this request
        Else request a new access token for the provided TSG and store it in the integration context and add the TSG ID
        as a prefix
        '''

        if previous_token.get(tsg_access_token) and previous_token.get(tsg_expiry_time) > date_to_timestamp(datetime.now()):
            return previous_token.get(tsg_access_token)
        else:
            tsg = f'tsg_id:{tsg_id}'
            data = {
                'grant_type': "client_credentials",
                'scope': tsg
            }
            try:
                headers = {
                    'Content-Type': 'application/x-www-form-urlencoded',

                }

                res = self._http_request(method='POST',
                                         full_url=self.oauth_url,
                                         auth=(self.client_id, self.client_secret),
                                         resp_type='response',
                                         headers=headers,
                                         data=data)
                try:
                    res = res.json()
                except ValueError as exception:
                    raise DemistoException('Failed to parse json object from response: {}'.format(res.content),
                                           exception)

                if res.get('access_token'):
                    expiry_time = date_to_timestamp(datetime.now(), date_format='%Y-%m-%dT%H:%M:%S')
                    expiry_time += res.get('expires_in', 0) * 1000 - 10
                    new_token = {
                        tsg_access_token: res.get('access_token'),
                        tsg_expiry_time: expiry_time
                    }
                    # store received token and expiration time in integration context
                    set_integration_context(new_token)
                    return res.get('access_token')

            except Exception as e:
                raise DemistoException(f'Error occurred while creating an access token. Please check the instance configuration.'
                                       f'\n\n{e.args[0]}')


def test_module(client: Client, args: dict, default_tsg_id: str):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.
    """
    uri = 'sse/config/v1/config-versions?limit=1'

    access_token = client.get_access_token(default_tsg_id)
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': f"Bearer {access_token}"
    }

    client._http_request(method='GET', url_suffix=uri, headers=headers)
    return CommandResults(
        raw_response="ok"
    )


def create_security_rule_command(client: Client, args: dict, default_tsg_id: str):

    # Create new Prisma Access security rule within the given Folder, Position, and Tenant/TSG

    rule = client.build_security_rule(args)

    if args.get('tsg_id'):
        tsg_id = args.get('tsg_id')
    else:
        tsg_id = default_tsg_id

    raw_response = client.create_security_rule(rule, args.get('folder'), args.get('position'), tsg_id)  # type: ignore
    outputs = raw_response

    return CommandResults(
        outputs_prefix='PrismaAccess.CreatedSecurityRule',
        outputs_key_field='id',
        outputs=outputs,
        readable_output=tableToMarkdown('Security Rule Created', outputs),
        raw_response=raw_response
    )


def delete_security_rule_command(client: Client, args: dict, default_tsg_id: str):

    # Delete the specified security rule within the targeted Prisma Access tenant / TSG

    rule_id = args.get('rule_id')
    if args.get('tsg_id'):
        tsg_id = args.get('tsg_id')
    else:
        tsg_id = default_tsg_id

    raw_response = client.delete_security_rule(rule_id, tsg_id)  # type: ignore
    outputs = raw_response

    return CommandResults(
        outputs_prefix='PrismaAccess.DeletedSecurityRule',
        outputs_key_field='id',
        outputs=outputs,
        readable_output=tableToMarkdown('Security Rule Deleted', outputs),
        raw_response=raw_response
    )


def query_agg_monitor_api_command(client: Client, args: dict, default_tsg_id: str):

    # send query to the Prisma SASE Multi-tenant cloud management portal aggregate monitoring API

    if args.get('tsg_id'):
        tsg_id = args.get('tsg_id')
    else:
        tsg_id = default_tsg_id

    if args.get('query_data'):
        query = json.loads(args.get('query_data'))  # type: ignore
    else:
        query = None

    raw_response = client.query_agg_monitor_api(tsg_id, args.get('uri'), query)  # type: ignore

    return CommandResults(
        readable_output=tableToMarkdown('Aggregate Monitor API Query Response', raw_response),
        raw_response=raw_response,
        outputs=raw_response,
        outputs_prefix='PrismaSASE.AggregateQueryResponse'
    )


def update_security_rule_command(client: Client, args: dict, default_tsg_id: str):

    # Update / Edit an existing Prisma Access security rule

    rule = client.build_security_rule(args)

    if args.get('tsg_id'):
        tsg_id = args.get('tsg_id')
    else:
        tsg_id = default_tsg_id

    raw_response = client.update_security_rule(rule, args.get(
        'folder'), args.get('position'), args.get('id'), tsg_id)  # type: ignore
    outputs = raw_response

    return CommandResults(
        outputs_prefix='PrismaAccess.UpdatedSecurityRule',
        outputs_key_field='id',
        outputs=outputs,
        readable_output=tableToMarkdown('Security Rule Updated', outputs),
        raw_response=raw_response
    )


def push_candidate_config_command(client: Client, args: dict, default_tsg_id: str):

    # Trigger a configuration push for the identified Folder/Devices

    devices = [x.strip() for x in args.get('devices').split(',')]  # type: ignore

    if args.get('tsg_id'):
        tsg_id = args.get('tsg_id')
    else:
        tsg_id = default_tsg_id

    raw_response = client.push_candidate_config(devices, args.get('description'), tsg_id)  # type: ignore

    outputs = raw_response

    return CommandResults(
        outputs_prefix='PrismaAccess.ConfigPush',
        outputs_key_field='id',
        outputs=outputs,
        readable_output=tableToMarkdown('Configuration Push Requested', outputs),
        raw_response=raw_response
    )


def list_security_rules_command(client: Client, args: dict, default_tsg_id: str):

   # Get all security rules for a given Prisma Access Folder / Position

    query_params = {
        'folder': encode_string_results(args.get('folder')),
        'position': encode_string_results(args.get('position'))
    }

    if args.get('tsg_id'):
        tsg_id = args.get('tsg_id')
    else:
        tsg_id = default_tsg_id

    if args.get('name'):
        query_params["name"] = encode_string_results(args.get('name'))

    if args.get('limit'):
        query_params["limit"] = encode_string_results(args.get('limit'))

    if args.get('offset'):
        query_params["offset"] = encode_string_results(args.get('offset'))

    raw_response = client.list_security_rules(query_params, tsg_id)  # type: ignore

    outputs = (raw_response)['data']

    return CommandResults(
        outputs_prefix='PrismaAccess.FoundSecurityRule',
        outputs_key_field='id',
        outputs=outputs,
        readable_output=tableToMarkdown('Security Rules', outputs),
        raw_response=raw_response
    )


def get_security_rule_by_name_command(client: Client, args: dict, default_tsg_id: str):

    # Get single security rule using the rule name as a filter

    query_params = {
        'folder': encode_string_results(args.get('folder')),
        'position': encode_string_results(args.get('position')),
        "name": args.get('name'),
        "limit": 1,
        "offset": 0
    }

    if args.get('tsg_id'):
        tsg_id = args.get('tsg_id')
    else:
        tsg_id = default_tsg_id

    raw_response = client.list_security_rules(query_params, tsg_id)  # type: ignore

    outputs = (raw_response)['data']

    return CommandResults(
        outputs_prefix='PrismaAccess.FoundSecurityRule',
        outputs_key_field='id',
        outputs=outputs,
        readable_output=tableToMarkdown('Security Rules', outputs),
        raw_response=raw_response
    )


def get_config_jobs_by_id_command(client: Client, args: dict, default_tsg_id: str):

    # List config jobs with a given id(s) for a given prisma access tenant

    job_ids = args.get('id')
    job_ids = job_ids.split(',')  # type: ignore

    if args.get('tsg_id'):
        tsg_id = args.get('tsg_id')
    else:
        tsg_id = default_tsg_id

    raw_response = []

    for job_id in job_ids:

        raw_response.append(client.get_config_jobs_by_id(tsg_id, job_id)['data'][0])  # type: ignore

    outputs = raw_response

    return CommandResults(
        outputs_prefix='PrismaAccess.ConfigJob',
        outputs_key_field='id',
        outputs=outputs,
        readable_output=tableToMarkdown('Config Jobs', outputs),
        raw_response=raw_response
    )


def list_config_jobs_command(client: Client, args: dict, default_tsg_id: str):

    # List all config jobs for a given prisma access tenant

    if args.get('tsg_id'):
        tsg_id = args.get('tsg_id')
    else:
        tsg_id = default_tsg_id

    query_params = {}

    if args.get('limit'):
        query_params["limit"] = encode_string_results(args.get('limit'))

    if args.get('offset'):
        query_params["offset"] = encode_string_results(args.get('offset'))

    raw_response = client.list_config_jobs(tsg_id, query_params)  # type: ignore

    outputs = (raw_response)['data']

    return CommandResults(
        outputs_prefix='PrismaAccess.ConfigJob',
        outputs_key_field='id',
        outputs=outputs,
        readable_output=tableToMarkdown('Config Job', outputs),
        raw_response=raw_response
    )


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    # get the service API url
    base_url = demisto.params()['url'].strip('/')
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    client_id = demisto.params().get('credentials').get('identifier')
    client_secret = demisto.params().get('credentials').get('password')
    oauth_url = demisto.params().get('oauth_url')
    default_tsg_id = demisto.params().get('tsg_id')

    LOG(f'Command being called is {demisto.command()}')

    commands = {
        'test-module': test_module,
        'prisma-access-create-security-rule': create_security_rule_command,
        'prisma-access-list-security-rules': list_security_rules_command,
        'prisma-access-push-candidate-config': push_candidate_config_command,
        'prisma-access-get-config-jobs-by-id': get_config_jobs_by_id_command,
        'prisma-access-list-config-jobs': list_config_jobs_command,
        'prisma-access-update-security-rule': update_security_rule_command,
        'prisma-access-get-security-rule-by-name': get_security_rule_by_name_command,
        'prisma-access-query-agg-monitor-api': query_agg_monitor_api_command,
        'prisma-access-delete-security-rule': delete_security_rule_command
    }

    command = demisto.command()

    client = Client(
        base_url=base_url,
        client_id=client_id,
        client_secret=client_secret,
        oauth_url=oauth_url,
        verify=verify_certificate,
        headers={
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        },
        proxy=proxy,
        ok_codes=(200, 201, 204))

    try:
        if command in commands:
            return_results(commands[command](client, demisto.args(), default_tsg_id))
        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
