import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
import sys
from base64 import b64encode
from typing import Any

import requests

from netmiko import Netmiko

''' Common setup '''

# server param is mandatory, no need to check if present
HOSTNAME = demisto.params()['server']

''' SSH integration  setup '''

sshConfigured = False

# Others are not mandatory as user may choose to only use XML API commands and not SSH
CREDS = demisto.params().get('Username', {})
USERNAME = CREDS.get('identifier')
PASSWORD = CREDS.get('password')
SSHPORT = demisto.params().get('sshport')
panos = {}

# Does user intend to leverage SSH commands
if USERNAME and PASSWORD and SSHPORT:
    sshConfigured = True
    panos = {
        'device_type': 'paloalto_panos',
        'ip': HOSTNAME,
        'username': USERNAME,
        'password': PASSWORD,
        'port': SSHPORT
    }


def panos_connect(net_connect: Netmiko = None):
    try:
        if not net_connect:
            net_connect = Netmiko(**panos)
        prompt = net_connect.find_prompt()
    finally:
        if net_connect:
            net_connect.disconnect()
    return prompt


def panos_ssh(cmd: str, net_connect: Netmiko = None):
    result_cmd = ''
    if sshConfigured:
        """
        Run any command
        """

    # execute command
        try:
            if not net_connect:
                net_connect = Netmiko(**panos)
                # Sometimes returns "debug", and will not wait for results
                result_cmd = net_connect.send_command_timing(cmd)

                # This command ensures the first has finished
                result_cmd += net_connect.send_command_timing("\n")
        finally:
            if net_connect:
                net_connect.disconnect()
                # Remove newlines and carriage returns
        return result_cmd.replace('\n', ' ').replace('\r', '')
    else:
        raise Exception('You must configure the SSH integration parameters to use this command.')


def prisma_access_cli_command():
    if sshConfigured:
        cmd = demisto.args().get('cmd')
        sshRes = panos_ssh(cmd)
        md = '### Prisma Access CLI Results\n' + sshRes
        ec = {"PrismaAccess.CLICommand": {'Command': cmd, 'Results': sshRes}}
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['text'],
            'Contents': sshRes,
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': md,
            'EntryContext': ec
        })
    else:
        raise Exception('You must configure the SSH integration parameters to use this command.')


def prisma_access_query():
    query = demisto.args().get('query')
    cmd = f'debug plugins cloud_services gpcs query {query}'
    sshRes = panos_ssh(cmd)
    jsonStartPos = sshRes.find('{"@status')
    if jsonStartPos < 0:
        return_outputs('Prisma Access returned non-JSON:\n%s' % (sshRes))
    else:
        res = json.loads(sshRes[jsonStartPos:])
        if res['@status'] == 'success':
            data = res.get('result', {}).get('entry', {})
            md = tableToMarkdown('Prisma Access Query Results', data)
            ec = {"PrismaAccess.QueryResults": data}
            contents = data
            return_outputs(md, ec, contents)
        else:
            resultsJsonAsText = json.dumps(res, indent=4)
            return_outputs(resultsJsonAsText, resultsJsonAsText, resultsJsonAsText)


def prisma_access_active_users():
    limit = demisto.args().get('limit', 20)
    cmd = f'debug plugins cloud_services gpcs query querystring limit={limit} action getGPaaSActiveUsers'
    sshRes = panos_ssh(cmd)
    jsonStartPos = sshRes.find('{"@status')
    if jsonStartPos < 0:
        return_outputs('Prisma Access returned non-JSON:\n%s' % (sshRes))
    else:
        res = json.loads(sshRes[jsonStartPos:])
        if res['@status'] == 'success':
            data = res.get('result', {}).get('entry', {})
            md = tableToMarkdown('Prisma Access Active Users', data)
            ec = {"PrismaAccess.ActiveUsers": data}
            contents = data
            return_outputs(md, ec, contents)
        else:
            resultsJsonAsText = json.dumps(res, indent=4)
            return_outputs(resultsJsonAsText, resultsJsonAsText, resultsJsonAsText)


''' API integration setup '''


# disable insecure warnings
requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]  # pylint: disable=no-member

''' GLOBALS '''
apiConfigured = False

# Others are not mandatory as user may choose to only use XML API commands and not SSH
KEY = secret_key = demisto.params().get('credentials_key', {}).get('password') or demisto.params().get('key', {})
PORT = demisto.params().get('port')

# Does user intend to leverage SSH commands
if KEY and PORT:
    apiConfigured = True

    URL = 'https://' + demisto.params()['server'].rstrip('/:') + ':' + PORT + '/api/'
    API_KEY = str(KEY)
    USE_SSL = not demisto.params().get('insecure')

    # determine a vsys or a device-group
    VSYS = demisto.params().get('vsys')
    if demisto.args() and demisto.args().get('device-group', None):
        DEVICE_GROUP = demisto.args().get('device-group')
    else:
        DEVICE_GROUP = demisto.params().get('device_group', None)

    # configuration check
    if DEVICE_GROUP and VSYS:
        return_error('Cannot configure both vsys and Device group. Set vsys for firewall, set Device group for Panorama.')
    if not DEVICE_GROUP and not VSYS:
        return_error('Set vsys for firewall or Device group for Panorama.')

    # setting security xpath relevant to FW or panorama management
    if DEVICE_GROUP:
        device_group_shared = DEVICE_GROUP.lower()
        if device_group_shared == 'shared':
            XPATH_SECURITY_RULES = "/config/shared/"
            DEVICE_GROUP = device_group_shared
        else:
            XPATH_SECURITY_RULES = "/config/devices/entry/device-group/entry[@name=\'" + DEVICE_GROUP + "\']/"
    else:
        XPATH_SECURITY_RULES = "/config/devices/entry/vsys/entry[@name=\'" + VSYS + "\']/rulebase/security/rules/entry"

    # setting objects xpath relevant to FW or panorama management
    if DEVICE_GROUP:
        device_group_shared = DEVICE_GROUP.lower()
        if DEVICE_GROUP == 'shared':
            XPATH_OBJECTS = "/config/shared/"
            DEVICE_GROUP = device_group_shared
        else:
            XPATH_OBJECTS = "/config/devices/entry/device-group/entry[@name=\'" + DEVICE_GROUP + "\']/"
    else:
        XPATH_OBJECTS = "/config/devices/entry/vsys/entry[@name=\'" + VSYS + "\']/"


PAN_OS_ERROR_DICT = {
    '1': 'Unknown command - The specific config or operational command is not recognized.',
    '2': 'Internal errors - Check with technical support when seeing these errors.',
    '3': 'Internal errors - Check with technical support when seeing these errors.',
    '4': 'Internal errors - Check with technical support when seeing these errors.',
    '5': 'Internal errors - Check with technical support when seeing these errors.',
    '6': 'Bad Xpath -The xpath specified in one or more attributes of the command is invalid.'
         'Check the API browser for proper xpath values.',
    '7': 'Object not present - Object specified by the xpath is not present. For example,'
         'entry[@name=value] where no object with name value is present.',
    '8': 'Object not unique - For commands that operate on a single object, the specified object is not unique.',
    '10': 'Reference count not zero - Object cannot be deleted as there are other objects that refer to it.'
          'For example, address object still in use in policy.',
    '11': 'Internal error - Check with technical support when seeing these errors.',
    '12': 'Invalid object - Xpath or element values provided are not complete.',
    '14': 'Operation not possible - Operation is allowed but not possible in this case.'
          'For example, moving a rule up one position when it is already at the top.',
    '15': 'Operation denied - Operation is allowed. For example, Admin not allowed to delete own account,'
          'Running a command that is not allowed on a passive device.',
    '16': 'Unauthorized -The API role does not have access rights to run this query.',
    '17': 'Invalid command -Invalid command or parameters.',
    '18': 'Malformed command - The XML is malformed.',
    # 19,20: success
    '21': 'Internal error - Check with technical support when seeing these errors.',
    '22': 'Session timed out - The session for this query timed out.'
}


class PAN_OS_Not_Found(Exception):
    """ PAN-OS Error. """


def http_request(uri: str, method: str, headers: dict = {},
                 body: dict = {}, params: dict = {}, files=None) -> Any:
    """
    Makes an API call with the given arguments
    """
    result = requests.request(
        method,
        uri,
        headers=headers,
        data=body,
        verify=USE_SSL,  # pylint: disable=E0606
        params=params,
        files=files
    )

    if result.status_code < 200 or result.status_code >= 300:
        raise Exception('Request Failed. with status: ' + str(result.status_code) + '. Reason is: ' + str(result.reason))

    # if pcap download
    if params.get('type') == 'export':
        return result

    json_result = json.loads(xml2json(result.text))

    # handle non success
    if json_result['response']['@status'] != 'success':
        if 'msg' in json_result['response'] and 'line' in json_result['response']['msg']:
            # catch non existing object error and display a meaningful message
            if json_result['response']['msg']['line'] == 'No such node':
                raise Exception(
                    'Object was not found, verify that the name is correct and that the instance was committed.')

            #  catch urlfiltering error and display a meaningful message
            elif str(json_result['response']['msg']['line']).find('test -> url') != -1:
                raise Exception('The URL filtering license is either expired or not active.'
                                ' Please contact your PAN-OS representative.')

            # catch non valid jobID errors and display a meaningful message
            elif isinstance(json_result['response']['msg']['line'], str) and \
                    json_result['response']['msg']['line'].find('job') != -1 and \
                    (json_result['response']['msg']['line'].find('not found') != -1
                     or json_result['response']['msg']['line'].find('No such query job')) != -1:
                raise Exception('Invalid Job ID error: ' + json_result['response']['msg']['line'])

            # catch already at the top/bottom error for rules and return this as an entry.note
            elif str(json_result['response']['msg']['line']).find('already at the') != -1:
                demisto.results('Rule ' + str(json_result['response']['msg']['line']))
                sys.exit(0)

            # catch already registered ip tags and return this as an entry.note
            elif str(json_result['response']['msg']['line']).find('already exists, ignore') != -1:
                if isinstance(json_result['response']['msg']['line']['uid-response']['payload']['register']['entry'],
                              list):
                    ips = [o['@ip'] for o in
                           json_result['response']['msg']['line']['uid-response']['payload']['register']['entry']]
                else:
                    ips = json_result['response']['msg']['line']['uid-response']['payload']['register']['entry']['@ip']
                demisto.results(
                    'IP ' + str(ips) + ' already exist in the tag. All submitted IPs were not registered to the tag.')
                sys.exit(0)

            # catch timed out log queries and return this as an entry.note
            elif str(json_result['response']['msg']['line']).find('Query timed out') != -1:
                demisto.results(str(json_result['response']['msg']['line']) + '. Rerun the query.')
                sys.exit(0)

        if '@code' in json_result['response']:
            raise Exception(
                'Request Failed.\nStatus code: ' + str(json_result['response']['@code']) + '\nWith message: ' + str(
                    json_result['response']['msg']['line']))
        else:
            raise Exception('Request Failed.\n' + str(json_result['response']))

    # handle @code
    if 'response' in json_result and '@code' in json_result['response']:
        if json_result['response']['@code'] in PAN_OS_ERROR_DICT:
            error_message = 'Request Failed.\n' + PAN_OS_ERROR_DICT[json_result['response']['@code']]
            if json_result['response']['@code'] == '7' and DEVICE_GROUP:
                device_group_names = get_device_groups_names()
                if DEVICE_GROUP not in device_group_names:
                    error_message += (f'\nDevice Group: {DEVICE_GROUP} does not exist.'
                                      f' The available Device Groups for this instance:'
                                      f' {", ".join(device_group_names)}.')
            raise PAN_OS_Not_Found(error_message)
        if json_result['response']['@code'] not in ['19', '20']:
            # error code non exist in dict and not of success
            if 'msg' in json_result['response']:
                raise Exception(
                    'Request Failed.\nStatus code: ' + str(json_result['response']['@code']) + '\nWith message: ' + str(
                        json_result['response']['msg']))
            else:
                raise Exception('Request Failed.\n' + str(json_result['response']))

    return json_result


def prisma_access_test():
    """
    test module
    """

    # Test API connection only if user configured it
    if apiConfigured:
        try:
            params = {
                'type': 'op',
                'cmd': '<show><system><info></info></system></show>',
                'key': API_KEY  # pylint: disable=E0606
            }

            http_request(
                URL,  # pylint: disable=E0606
                'GET',
                params=params
            )

            if DEVICE_GROUP and DEVICE_GROUP != 'shared':
                device_group_test()
        except Exception as ex:
            raise type(ex)("PAN-OS XML API Test:\n" + str(ex))

    # Test SSH connection only if user configured it
    if sshConfigured:
        try:
            panos_connect()
        except Exception as ex:
            raise type(ex)("PAN-OS SSH CLI Test:\n" + str(ex))

    # If reached this point, all ok
    demisto.results('ok')


def get_device_groups_names():
    """
    Get device group names in the Panorama
    """
    params = {
        'action': 'get',
        'type': 'config',
        'xpath': "/config/devices/entry/device-group/entry",
        'key': API_KEY
    }

    result = http_request(
        URL,
        'GET',
        params=params
    )

    device_groups = result['response']['result']['entry']
    device_group_names = []
    if isinstance(device_groups, dict):
        # only one device group in the panorama
        device_group_names.append(device_groups.get('@name'))
    else:
        for device_group in device_groups:
            device_group_names.append(device_group.get('@name'))

    return device_group_names


def device_group_test():
    """
    Test module for the Device group specified
    """
    device_group_names = get_device_groups_names()
    if DEVICE_GROUP not in device_group_names:
        raise Exception(f'Device Group: {DEVICE_GROUP} does not exist.'
                        f' The available Device Groups for this instance: {", ".join(device_group_names)}.')


@logger
def prisma_access_logout_user(computer: str, domain: str, user: str, tenant: str) -> dict[str, str]:
    if apiConfigured:
        xmlComputer = '<computer>%s</computer>' % b64encode(computer.encode('utf8')).decode('utf8') if computer else ''
        b64User = (b64encode(user.encode('utf8'))).decode('utf8')
        cmd = ''
        if domain:
            cmd = '''<request><plugins><cloud_services><gpcs>
                  <logout_mobile_user><gateway>{}<domain>{}</domain><user>{}</user></gateway></logout_mobile_user>
                  </gpcs></cloud_services></plugins></request>'''.format(xmlComputer, domain, b64User)
        else:
            cmd = '''<request><plugins><cloud_services><gpcs>
                  <logout_mobile_user><gateway>{}<user>{}</user></gateway></logout_mobile_user>
                  </gpcs></cloud_services></plugins></request>'''.format(xmlComputer, b64User)

        if tenant:
            tenant_entry = f"<multi-tenant><tenant-name><entry name='{tenant}'></entry></tenant-name>"
            cmd = cmd.replace('<gpcs>', f'<gpcs>{tenant_entry}').replace('</logout_mobile_user>',
                                                                         '</logout_mobile_user></multi-tenant>')
        params = {
            'type': 'op',
            'key': API_KEY,
            'cmd': cmd
        }
        result = http_request(URL, 'GET', params=params)
        return result
    else:
        raise Exception('You must configure the PAN-OS API Key and Port parameters to use this command.')


def prisma_access_logout_user_command():
    computer = demisto.args().get('computer', '')
    domain = demisto.args().get('domain', '')
    user = demisto.args().get('user', '')
    tenant = demisto.args().get('tenant_name', '')

    result = prisma_access_logout_user(computer, domain, user, tenant)

    if 'result' in result['response'] and result['response']['@status'] == 'success':
        res = result['response'].get('result', '')
        hr = '### Prisma Access Logout Results:\n' + json.dumps(res, indent=4)
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': res,
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': hr,
            'EntryContext': {
                'PrismaAccess.LogoutUser': res
            }
        })
    else:
        demisto.results(result)


def main():
    LOG(f'Command being called is: {demisto.command()}')

    try:
        # Remove proxy if not set to true in params
        handle_proxy()

        if demisto.command() == 'test-module':
            prisma_access_test()

        elif demisto.command() == 'prisma-access-logout-user':
            prisma_access_logout_user_command()

        elif demisto.command() == 'prisma-access-query':
            prisma_access_query()

        elif demisto.command() == 'prisma-access-active-users':
            prisma_access_active_users()

        elif demisto.command() == 'prisma-access-cli-command':
            prisma_access_cli_command()

        else:
            raise NotImplementedError(f'Command {demisto.command()} was not implemented.')

    except Exception as err:
        return_error(str(err))

    finally:
        LOG.print_log()


if __name__ in ["__builtin__", "builtins"]:
    main()
