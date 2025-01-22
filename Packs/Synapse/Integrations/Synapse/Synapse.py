import asyncio
import ipaddress
import json

import aiohttp
import pytz
import urllib3
from CommonServerPython import *
from aiohttp import TCPConnector

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y/%m/%d %H:%M:%S %Z'
TIMEZONE = demisto.params().get('timezone', None)

''' CLIENT '''


class Client(BaseClient):
    """
    Client class to interact with the service API
    """

    def __init__(self, base_url, username, password, proxy, **kwargs):
        self._base_url = base_url
        self.username = username
        self.password = password
        self.proxy = proxy
        self.auth = (username, password)
        self.aio_auth = aiohttp.BasicAuth(username, password)
        super().__init__(base_url, **kwargs)

    def _check_for_error(self, resp):
        """
        Checks for custom synapse error message in JSON response.
        Raises error if so.
        """
        if resp.get('status') != 'ok':
            code = resp.get('code')
            mesg = resp.get('mesg')
            raise Exception(f'Synapse API Error: ({code}): {mesg}')

    def login(self):
        """
        Login to Synapse and validate credentials.
        """

        resp = self._http_request(
            method='POST',
            url_suffix='/login',
            json_data={"user": self.username, "passwd": self.password}
        )

        self._check_for_error(resp)

        return resp

    def add_user(self, new_user, new_passwd):
        """
        Adds a new user to Synapse with given password.
        """

        resp = self._http_request(
            method='POST',
            url_suffix='/auth/adduser',
            json_data={'name': new_user, 'passwd': new_passwd},
            auth=self.auth
        )

        self._check_for_error(resp)

        return resp

    def add_role(self, new_role):
        """
        Adds a new user role to Synapse.
        """

        resp = self._http_request(
            method='POST',
            url_suffix='/auth/addrole',
            json_data={'name': new_role},
            auth=self.auth
        )

        self._check_for_error(resp)

        return resp

    def grant_role(self, user, role):
        """
        Adds a new user role to Synapse.
        """

        resp = self._http_request(
            method='POST',
            url_suffix='/auth/grant',
            json_data={'user': user, 'role': role},
            auth=self.auth
        )

        self._check_for_error(resp)

        return resp

    def list_users(self):
        """
        Collects all users in Synapse.
        """

        resp = self._http_request(
            method='GET',
            url_suffix='/auth/users',
            auth=self.auth
        )

        self._check_for_error(resp)

        return resp

    def list_roles(self):
        """
        Collects all user roles in Synapse.
        """

        resp = self._http_request(
            method='GET',
            url_suffix='/auth/roles',
            auth=self.auth
        )

        self._check_for_error(resp)

        return resp

    def get_model(self):
        """
        Queries and returns full model json.
        """

        resp = self._http_request(
            method='GET',
            url_suffix='/model',
            auth=self.auth
        )

        self._check_for_error(resp)

        return resp

    async def synapse_get_nodes(self, data, limit=100):
        """
        Async function to query for Synapse nodes via storm.
        """
        my_query = f'{data} | limit {limit}'
        nodes = []  # Nodes to return
        async with aiohttp.ClientSession(
                connector=TCPConnector(ssl=self._verify),
                trust_env=self.proxy
        ) as sess:
            address = urljoin(self._base_url, '/storm')
            query = {'query': my_query}
            async with sess.get(address, json=query, auth=self.aio_auth) as resp:
                async for byts, _x in resp.content.iter_chunks():
                    if not byts:
                        break
                    mesg = json.loads(byts)
                    if mesg[0] == 'node':
                        nodes.append(mesg[1])
        return nodes


''' HELPER FUNCTIONS '''


def validate_timezone_helper(TIMEZONE):
    """
    Validates Timezone format is correct before assuming it is.
    """
    if TIMEZONE not in pytz.all_timezones:
        return_error(f'Error: Timezone format "{TIMEZONE}" invalid')
    else:
        tz = pytz.timezone(TIMEZONE)
    return tz  # pylint: disable=E0606


def convert_raw_into_nodes_helper(results):
    """
    Accepts raw node json and returns formatted list of dicts (nodes).
    """

    nodes = []
    for item in results:
        t_stamp = convert_epoch_timestamp_helper(item[1]['props'].get('.created'))
        node = {
            'form': item[0][0],
            'created': t_stamp,
            'tags': get_full_tags_helper(item[1].get('tags'))
        }
        if item[0][0] == 'inet:ipv4':
            node['valu'] = ipaddress.ip_address(item[0][1]).__str__()
        else:
            node['valu'] = item[0][1]
        nodes.append(node)
    return nodes


def get_full_tags_helper(data):
    """
    Accepts raw REST Response for tags key and returns list of longest heirarchical tags.
    """
    tags = []

    temp_tags = list(data.keys())
    if temp_tags:
        tags.append(temp_tags.pop(0))
    else:
        return tags

    for _i in range(0, len(temp_tags)):
        if temp_tags:
            temp = temp_tags.pop(0)
        else:
            break
        for tag in tags:
            if temp in tag:
                continue
            elif tag in temp:
                tags.remove(tag)
                tags.append(temp)
            else:
                tags.append(temp)
    return tags


def convert_epoch_timestamp_helper(timestamp):
    """
    Accepts Epoch timestamp and localizes to UTC (timestamps per Synapse are all in UTC).
    """

    raw_date = datetime.fromtimestamp(float(timestamp) / 1000.)
    utc_date = raw_date.replace(tzinfo=pytz.UTC)

    if TIMEZONE:
        tz = validate_timezone_helper(TIMEZONE)
        current_date = utc_date.astimezone(tz)
        return current_date.strftime(DATE_FORMAT)
    else:
        return utc_date.strftime(DATE_FORMAT)


def model_query_helper(model, query):
    """
    Accepts model (full json) and a node type (str) to query.
    Returns properties for given node type. Raises error not found if not present.
    """
    parsed_data = {'query': query}
    mod_types = list(model['types'].keys())
    mod_forms = list(model['forms'].keys())

    if (query not in mod_types) and (query not in mod_forms):
        raise Exception(f'Error: Query "{query}" not found in model. Try adjusting syntax (i.e. "inet:ipv4").')

    parsed_data['type'] = model['types'].get(query)

    if query in mod_forms:
        parsed_data['form'] = model['forms'].get(query)

    return parsed_data


def model_query_properties_helper(form):
    """
    Accepts JSON of cortex form and returns formatted properties.
    """
    data = {}
    for prop, valu in form.get('props').items():
        data[prop] = valu.get('doc', 'N/A')

    return data


def user_roles_helper(client, roles):
    """
    Accepts list of role identifiers and converts them to named roles. Return list of names.
    """
    data = client.list_roles()
    named_roles = []

    for role in data.get('result'):
        if role.get('iden') in roles:
            named_roles.append(role.get('name'))

    return named_roles


def user_rules_helper(rules):
    """
    Accepts REST rules response and returns list of joined rules.
    """
    new_rules = []
    if not rules:
        return rules
    for rule in rules:
        if rule[0]:
            new_rules.append('.'.join(rule[1]))
    return new_rules


def file_regex_helper(hash):
    """
    Accepts a raw hash and regex matches to determine what type.
    """

    if re.match(md5Regex, hash):
        file_query = f'file:bytes:md5={hash}'
    elif re.match(sha1Regex, hash):
        file_query = f'file:bytes:sha1={hash}'
    elif re.match(sha256Regex, hash):
        file_query = f'file:bytes:sha256={hash}'
    elif re.match(sha512Regex, hash):
        file_query = f'file:bytes:sha512={hash}'
    else:
        raise ValueError(f'Value "{hash}" is not a valid File Hash.')

    return file_query


def file_context_builder_helper(file, data):
    """
    Accepts hash and parsed query response. Adds MD5, SHA1, SHA256, SHA512.
    """
    file_context = {
        'hash': file,
        'tags': get_full_tags_helper(data[0][1].get('tags'))
    }
    if data[0][1]['props'].get('md5'):
        file_context['MD5'] = data[0][1]['props'].get('md5')
    if data[0][1]['props'].get('sha1'):
        file_context['SHA1'] = data[0][1]['props'].get('sha1')
    if data[0][1]['props'].get('sha256'):
        file_context['SHA256'] = data[0][1]['props'].get('sha256')
    if data[0][1]['props'].get('sha512'):
        file_context['SHA512'] = data[0][1]['props'].get('sha512')

    return file_context


''' COMMAND FUNCTIONS '''


def test_module(client):
    """
    Tests API connectivity and authentication'
    """
    client.login()
    return 'ok'


def ip_reputation_command(client, args, good_tag, bad_tag) -> List[CommandResults]:
    """
    Returns IP Reputation for a list of IPs.
    """
    ips = argToList(args.get('ip'))
    if len(ips) == 0:
        raise ValueError('IP(s) not specified')

    for ip in ips:
        if not re.match(ipv4Regex, ip):
            raise ValueError(f'Value "{ip}" is not a valid IP address.')

    command_results: List[CommandResults] = []
    for ip in ips:
        query = f'inet:ipv4={ip}'
        data = asyncio.run(client.synapse_get_nodes(query))
        if not data:
            continue
        ip_data = {
            'ip': ip,
            'tags': get_full_tags_helper(data[0][1].get('tags'))
        }

        score = Common.DBotScore.NONE  # unknown
        reputation = {'tag': 'N/A'}
        if bad_tag in ip_data['tags']:
            score = Common.DBotScore.BAD  # bad
            reputation['tag'] = bad_tag
        elif good_tag in ip_data['tags']:
            score = Common.DBotScore.GOOD  # good
            reputation['tag'] = good_tag

        # Create the DBotScore structure first using the Common.DBotScore class.
        dbot_score = Common.DBotScore(
            indicator=ip,
            indicator_type=DBotScoreType.IP,
            integration_name='Synapse',
            score=score,
            malicious_description=f'Synapse returned reputation tag: {reputation["tag"]}',
            reliability=demisto.params().get('integrationReliability')
        )

        # Create the IP Standard Context structure using Common.IP and add
        # dbot_score to it.
        ip_standard_context = Common.IP(
            ip=ip,
            dbot_score=dbot_score
        )

        command_results.append(CommandResults(
            readable_output=tableToMarkdown('IP Details', ip_data),
            outputs_prefix='Synapse.IP',
            outputs_key_field='ip',
            outputs=ip_data,
            indicator=ip_standard_context
        ))

    return command_results


def domain_reputation_command(client, args, good_tag, bad_tag) -> List[CommandResults]:
    """
    Returns Domain Reputation for a list of Domains.
    """
    domains = argToList(args.get('domain'))
    if len(domains) == 0:
        raise ValueError('Domain(s) not specified')

    command_results: List[CommandResults] = []
    for domain in domains:
        query = f'inet:fqdn={domain}'
        data = asyncio.run(client.synapse_get_nodes(query))
        if not data:
            continue
        domain_data = {
            'domain': domain,
            'tags': get_full_tags_helper(data[0][1].get('tags'))
        }

        score = Common.DBotScore.NONE  # unknown
        reputation = {'tag': 'N/A'}
        if bad_tag in domain_data['tags']:
            score = Common.DBotScore.BAD  # bad
            reputation['tag'] = bad_tag
        elif good_tag in domain_data['tags']:
            score = Common.DBotScore.GOOD  # good
            reputation['tag'] = good_tag

        # Create the DBotScore structure first using the Common.DBotScore class.
        dbot_score = Common.DBotScore(
            indicator=domain,
            indicator_type=DBotScoreType.DOMAIN,
            integration_name='Synapse',
            score=score,
            malicious_description=f'Synapse returned reputation tag: {reputation["tag"]}',
            reliability=demisto.params().get('integrationReliability')
        )

        # Create the Domain Standard Context structure using Common.Domain and add
        # dbot_score to it.
        domain_standard_context = Common.Domain(
            domain=domain,
            dbot_score=dbot_score
        )

        command_results.append(CommandResults(
            readable_output=tableToMarkdown('Domain Details', domain_data),
            outputs_prefix='Synapse.Domain',
            outputs_key_field='domain',
            outputs=domain_data,
            indicator=domain_standard_context
        ))

    return command_results


def url_reputation_command(client, args, good_tag, bad_tag) -> List[CommandResults]:
    """
    Returns URL Reputation for a list of URLs.
    """
    urls = argToList(args.get('url'))
    if len(urls) == 0:
        raise ValueError('URL(s) not specified')

    for url in urls:
        if not re.match(urlRegex, url):
            raise ValueError(f'Value "{url}" is not a valid URL address.')

    command_results: List[CommandResults] = []
    for url in urls:
        query = f'inet:url={url}'
        data = asyncio.run(client.synapse_get_nodes(query))
        if not data:
            continue
        url_data = {
            'url': url,
            'tags': get_full_tags_helper(data[0][1].get('tags'))
        }

        score = Common.DBotScore.NONE  # unknown
        reputation = {'tag': 'N/A'}
        if bad_tag in url_data['tags']:
            score = Common.DBotScore.BAD  # bad
            reputation['tag'] = bad_tag
        elif good_tag in url_data['tags']:
            score = Common.DBotScore.GOOD  # good
            reputation['tag'] = good_tag

        # Create the DBotScore structure first using the Common.DBotScore class.
        dbot_score = Common.DBotScore(
            indicator=url,
            indicator_type=DBotScoreType.URL,
            integration_name='Synapse',
            score=score,
            malicious_description=f'Synapse returned reputation tag: {reputation["tag"]}',
            reliability=demisto.params().get('integrationReliability')
        )

        # Create the URL Standard Context structure using Common.URL and add
        # dbot_score to it.
        url_standard_context = Common.URL(
            url=url,
            dbot_score=dbot_score
        )

        command_results.append(CommandResults(
            readable_output=tableToMarkdown('URL Details', url_data),
            outputs_prefix='Synapse.URL',
            outputs_key_field='url',
            outputs=url_data,
            indicator=url_standard_context
        ))

    return command_results


def file_reputation_command(client, args, good_tag, bad_tag) -> List[CommandResults]:
    """
    Returns File Reputation for a list of hashes (MD5, SHA1, or SHA256).
    """
    files = argToList(args.get('file'))
    if len(files) == 0:
        raise ValueError('File(s) not specified')

    command_results: List[CommandResults] = []
    for file in files:
        file_query = file_regex_helper(file)
        data = asyncio.run(client.synapse_get_nodes(file_query))
        if not data:
            continue
        file_data = file_context_builder_helper(file, data)
        file_data['query'] = file_query

        score = Common.DBotScore.NONE  # unknown
        reputation = {'tag': 'N/A'}
        if bad_tag in file_data['tags']:
            score = Common.DBotScore.BAD  # bad
            reputation['tag'] = bad_tag
        elif good_tag in file_data['tags']:
            score = Common.DBotScore.GOOD  # good
            reputation['tag'] = good_tag

        # Create the DBotScore structure first using the Common.DBotScore class.
        dbot_score = Common.DBotScore(
            indicator=file,
            indicator_type=DBotScoreType.FILE,
            integration_name='Synapse',
            score=score,
            malicious_description=f'Synapse returned reputation tag: {reputation["tag"]}',
            reliability=demisto.params().get('integrationReliability')
        )

        # Create the File Standard Context structure using Common.File and add
        # dbot_score to it.
        file_standard_context = Common.File(
            md5=file_data.get('MD5'),
            sha1=file_data.get('SHA1'),
            sha256=file_data.get('SHA256'),
            sha512=file_data.get('SHA512'),
            dbot_score=dbot_score
        )

        command_results.append(CommandResults(
            readable_output=tableToMarkdown('File Details', file_data),
            outputs_prefix='Synapse.File',
            outputs_key_field='hash',
            outputs=file_data,
            indicator=file_standard_context
        ))

    return command_results


def storm_query_command(client, args):
    """
    Executes a storm query and expects nodes in response.
    """
    try:
        data = asyncio.run(client.synapse_get_nodes(args.get('query'), args.get('limit')))
    except DemistoException as e:
        if 'AuthDeny' in str(e):
            return 'Authorization Error: make sure credentials are correct set'
        else:
            raise e
    else:
        nodes = convert_raw_into_nodes_helper(data)

    name = f'Synapse Query Results: `{args.get("query")}`'
    headers = ['form', 'valu', 'created', 'tags']
    readable_output = tableToMarkdown(name, nodes, headers=headers, removeNull=True)

    if len(nodes) == 1:
        name_single = 'Synapse Node Properties'
        headers_single = list(data[0][1]['props'].keys())
        readable_output += tableToMarkdown(name_single, data[0][1]['props'], headers=headers_single, removeNull=False)

    results = CommandResults(
        outputs_prefix='Synapse.Nodes',
        outputs_key_field='valu',
        outputs=nodes,
        readable_output=readable_output,
        raw_response=data
    )

    return results


def list_users_command(client):
    """
    Executes API call for list users and returns response.
    """

    data = client.list_users()
    users = []

    for user in data.get('result'):
        my_user = {
            'Name': user.get('name'),
            'Email': user.get('email'),
            'Admin': user.get('admin'),
            'Iden': user.get('iden'),
            'Rules': user_rules_helper(user.get('rules')),
            'Roles': user_roles_helper(client, user.get('roles'))
        }
        users.append(my_user)

    name = 'Synapse Users'
    headers = ['Name', 'Email', 'Admin', 'Rules', 'Roles']
    readable_output = tableToMarkdown(name, users, headers=headers, removeNull=False)

    results = CommandResults(
        outputs_prefix='Synapse.Users',
        outputs_key_field='Iden',
        outputs=users,
        readable_output=readable_output,
        raw_response=data
    )

    return results


def list_roles_command(client):
    """
    Executes API call for list roles and returns response.
    """

    data = client.list_roles()
    roles = []

    for role in data.get('result'):
        my_role = {
            'Name': role.get('name'),
            'Iden': role.get('iden'),
            'Rules': user_rules_helper(role.get('rules'))
        }
        roles.append(my_role)

    name = 'Synapse Roles'
    headers = ['Name', 'Iden', 'Rules']
    readable_output = tableToMarkdown(name, roles, headers=headers, removeNull=False)

    results = CommandResults(
        outputs_prefix='Synapse.Roles',
        outputs_key_field='Iden',
        outputs=roles,
        readable_output=readable_output,
        raw_response=data
    )

    return results


def add_user_command(client, args):
    """
    Add a user to Synapse. Accepts username and password.
    """

    data = client.add_user(args.get('username'), args.get('password'))
    user = data.get('result')

    my_user = {
        'Name': user.get('name'),
        'Email': user.get('email'),
        'Admin': user.get('admin'),
        'Iden': user.get('iden'),
        'Rules': user_rules_helper(user.get('rules')),
        'Roles': user_roles_helper(client, user.get('roles'))
    }

    name = 'Synapse New User'
    headers = ['Name', 'Email', 'Admin', 'Rules', 'Roles']
    readable_output = tableToMarkdown(name, my_user, headers=headers, removeNull=False)

    results = CommandResults(
        outputs_prefix='Synapse.Users',
        outputs_key_field='Iden',
        outputs=my_user,
        readable_output=readable_output,
        raw_response=data
    )

    return results


def add_role_command(client, args):
    """
    Add a role to Synapse. Accepts new role.
    """

    data = client.add_role(args.get('role'))
    role = data.get('result')

    my_role = {
        'Name': role.get('name'),
        'Iden': role.get('iden'),
        'Rules': user_rules_helper(role.get('rules')),
    }

    name = 'Synapse New Role'
    headers = ['Name', 'Iden', 'Rules']
    readable_output = tableToMarkdown(name, my_role, headers=headers, removeNull=False)

    results = CommandResults(
        outputs_prefix='Synapse.Roles',
        outputs_key_field='Iden',
        outputs=my_role,
        readable_output=readable_output,
        raw_response=data
    )

    return results


def grant_user_role_command(client, args):
    """
    Grant role to a user.
    """

    data = client.grant_role(args.get('user'), args.get('role'))

    user = data.get('result')

    my_user = {
        'Name': user.get('name'),
        'Email': user.get('email'),
        'Admin': user.get('admin'),
        'Iden': user.get('iden'),
        'Rules': user_rules_helper(user.get('rules')),
        'Roles': user_roles_helper(client, user.get('roles'))
    }

    name = 'Synapse New User Role'
    headers = ['Name', 'Email', 'Admin', 'Rules', 'Roles']
    readable_output = tableToMarkdown(name, my_user, headers=headers, removeNull=False)

    results = CommandResults(
        outputs_prefix='Synapse.Users',
        outputs_key_field='Iden',
        outputs=my_user,
        readable_output=readable_output,
        raw_response=data
    )

    return results


def query_model_command(client, args):
    """
    Accepts a node type (str) to query and returns docs and properties.
    """

    data = client.get_model()
    model_resp = model_query_helper(data.get('result'), args.get('query').lower())
    q_type, q_form = {}, {}

    if model_resp.get('type'):
        q_type = {
            'Type': model_resp.get('query'),
            'Doc': model_resp['type']['info'].get('doc', 'N/A'),
            'Example': model_resp['type']['info'].get('ex', 'N/A')
        }
    if model_resp.get('form'):
        q_form = {
            'Form': model_resp.get('query'),
            'Properties': model_query_properties_helper(model_resp.get('form'))
        }
    full_resp = {
        'Valu': model_resp.get('query')
    }

    full_resp.update(q_type)
    full_resp.update(q_form)

    name = 'Synapse Model Type'
    headers = ['Type', 'Doc', 'Example']
    readable_output = tableToMarkdown(name, q_type, headers=headers, removeNull=False)

    if full_resp.get('Form'):
        name_form = f'Synapse `{full_resp.get("Valu")}` Form Properties'
        headers_form = list(q_form['Properties'].keys())
        readable_output += tableToMarkdown(name_form, q_form['Properties'], headers=headers_form, removeNull=False)

    results = CommandResults(
        outputs_prefix='Synapse.Model',
        outputs_key_field='Valu',
        outputs=full_resp,
        readable_output=readable_output,
        raw_response=model_resp
    )

    return results


''' MAIN FUNCTION '''


def main() -> None:
    """
    main function, parses params and runs command functions
    """
    username = demisto.params().get('credentials').get('identifier')
    password = demisto.params().get('credentials').get('password')
    port = demisto.params().get('port')
    base = demisto.params()['url'].rstrip('/') + ':' + str(port)
    use_ssl = not demisto.params().get('insecure', False)
    use_proxy = demisto.params().get('proxy', False)
    good_tag = demisto.params().get('good_tag')
    bad_tag = demisto.params().get('bad_tag')
    use_optic = demisto.params().get('use_optic', False)
    if use_optic:
        base_url = urljoin(base, '/api/v1/optic')
    else:
        base_url = urljoin(base, '/api/v1')

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url=base_url,
            username=username,
            password=password,
            verify=use_ssl,
            proxy=use_proxy
        )

        if demisto.command() == 'test-module':
            return_results(test_module(client))

        elif demisto.command() == 'ip':
            return_results(ip_reputation_command(client, demisto.args(), good_tag, bad_tag))

        elif demisto.command() == 'domain':
            return_results(domain_reputation_command(client, demisto.args(), good_tag, bad_tag))

        elif demisto.command() == 'url':
            return_results(url_reputation_command(client, demisto.args(), good_tag, bad_tag))

        elif demisto.command() == 'file':
            return_results(file_reputation_command(client, demisto.args(), good_tag, bad_tag))

        elif demisto.command() == 'synapse-storm-query':
            return_results(storm_query_command(client, demisto.args()))

        elif demisto.command() == 'synapse-list-users':
            return_results(list_users_command(client))

        elif demisto.command() == 'synapse-list-roles':
            return_results(list_roles_command(client))

        elif demisto.command() == 'synapse-create-user':
            return_results(add_user_command(client, demisto.args()))

        elif demisto.command() == 'synapse-create-role':
            return_results(add_role_command(client, demisto.args()))

        elif demisto.command() == 'synapse-grant-user-role':
            return_results(grant_user_role_command(client, demisto.args()))

        elif demisto.command() == 'synapse-query-model':
            return_results(query_model_command(client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
