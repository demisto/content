register_module_line('FortiMail', 'start', __line__())

'''Demisto Imports'''
# import demistomock as demisto
# from CommonServerPython import *
# from CommonServerUserPython import *


''' IMPORTS '''
import json
import urllib3
#from .const import *
from datetime import datetime
from typing import Callable, Tuple

# Disable insecure warnings
urllib3.disable_warnings()

'''Constants'''
conn_setting = ['conn_rate_how_many', 'number_of_messages', 'number_of_recipients', 'conn_concurrent',
                'conn_idle_timeout']

sender_reputations = ['sender_reputation_throttle', 'sender_reputation_throttle_number',
                        'sender_reputation_throttle_percent', 'sender_reputation_tempfail', 'sender_reputation_reject']

sender_reputations2 = ['sender_reputation', 'check_client_ip_quick']

endpoint_reputation = ['msisdn_sender_reputation_trigger', 'msisdn_sender_reputation_blacklist_duration']

sender_validation = ['dkim', 'dkim_signing', 'dkim_signing_authenticated_only', 'domainkey', 'bypass_bounce_verify',
                        'sender_verification']

session_settings = ['check_domain_chars', 'command_checking', 'eom_ack']

lists = ['whitelist_enable', 'blacklist_enable', 'to_whitelist_enable', 'to_blacklist_enable']

action_types = {"Reject": 0, "Monitor": 1}

enable_values = {"Enable": True, "Disable": False}

actions = {"None": "<None>", "Default": "", "Discard": "Discard", "Reject": "Reject",
            "System Quarantine": "SystemQuarantine", "User Quarantine": "UserQuarantine", "Tag Subject": "TagSubject"}

scan_config = ['greylist', 'spf_checking', 'dmarc_status', 'behavior_analysis', 'deepheader_check_ip', 'imagespam',
                'aggressive']
spf_options = ['spf_fail_status', 'spf_soft_fail_status', 'spf_sender_alignment_status', 'spf_perm_error_status',
                'spf_temp_error_status', 'spf_pass_status', 'spf_neutral_status', 'spf_none_status']
spf_actions = ['action_spf_fail', 'action_spf_soft_fail', 'action_spf_sender_alignment', 'action_spf_perm_error',
                'action_spf_temp_error', 'action_spf_pass', 'action_spf_neutral', 'action_spf_none']
action_list = ['action_dmarc', 'action_behavior_analysis', 'scanner_deep_header', 'scanner_image_spam']

ACTION_MAP = {
    'Add': '2',
    'Remove': '3'
}

ACCOUNT_TYPE_MAP = {
    "System Quarantine": 2,
    "Personal Quarantine": 3
}

RELEASE_ENDPOINT_MAP = {
    "System Quarantine": "SystemQuarantineRelease",
    "Personal Quarantine": "PersonalQuarantineRelease"
}

REQ_ACTION = 7

USERNAME =demisto.params().get('credentials').get('identifier')
PASSWORD = demisto.params().get('credentials').get('password')
PASS_token = demisto.params().get('credentials').get('password')
SERVER = demisto.params()['server'][:-1] if (demisto.params()['server'] and demisto.params()
                                                ['server'].endswith('/')) else demisto.params()['server']
USE_SSL = not demisto.params().get('unsecure', False)
BASE_URL = SERVER + '/api/v2/'

'''Base Client'''

class Client(BaseClient):
    """Client class to interact with the service API
    """

    def __init__(self, base_url: str, verify: bool, proxy: bool, username, password):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.username = username,
        self.password = password

    def fortimail_login(self):
        data = {"name":USERNAME,
                "password":PASSWORD}
        headers = {'Content-type': 'application/json'}
        #print(self.username)
        #demisto.info(data)
        session= requests.Session()
        session.trust_env= False
        Login_url=BASE_URL+'AdminLogin'
        session.post(Login_url,headers=headers,data=json.dumps(data),verify=False)
        return session
        #return self._http_request('POST', 'https://172.25.1.88/api/v1/AdminLogin', data=json.dumps(data), headers=headers)

    def get_domains_request(self):

        self.fortimail_login()

        return self._http_request("GET", "domain")

    def get_antispam_domains_request(self, params):

        self.fortimail_login()

        domain = params.get('domain')

        endpoint = "domain/{0}/ProfAntispam/".format(domain)

        return self._http_request("GET", endpoint)

    def get_recipient_policies_request(self):

        self.fortimail_login()

        endpoint = "domain/{0}/PolicyRcpt/".format(params.get('domain'))

        return self._http_request("GET", endpoint)

    def grey_list_request(self):

        self.fortimail_login()

        return self._http_request("GET", "AsGreylist")

    def get_session_safe_list_request(self, config, params):

        self.fortimail_login()

        return manage_profile(config, params, 'ProfSession/{0}/ProfSessionSenderWhitelist/', 'GET')

    def get_session_block_list_request(self, config, params):

        self.fortimail_login()

        return manage_profile(config, params, 'ProfSession/{0}/ProfSessionSenderBlacklist/', 'GET')

    def update_block_list_request(self, config, params):

        self.fortimail_login()

        return manage_list(config, params, 'blocklist')

    def update_safe_list_request(self, config, params):

        self.fortimail_login()

        return manage_list(config, params, 'safelist')

    def block_sender_address_request(self, params):

        session=self.fortimail_login()
        urladdress= BASE_URL+"ProfSession/{0}/ProfSessionSenderBlacklist/{1}".format(demisto.args().get('Profile_name'),demisto.args().get('Sender_Email_address'))
        demisto.results(session.post(urladdress,verify=False).json())
        #return self._http_request('POST', params, 'ProfSession/{0}/ProfSessionSenderBlacklist/{1}')

    def block_recipient_address_request(self, params):

        session=self.fortimail_login()

        urladdress= BASE_URL+"ProfSession/{0}/ProfSessionRecipientBlacklist/{1}".format(demisto.args().get('Profile_name'),demisto.args().get('Recipient_Email_address'))

        demisto.results(session.post(urladdress,verify=False).json())

        #return self._http_request('POST', params, 'ProfSession/{0}/ProfSessionRecipientBlacklist/{1}')

    def unblock_sender_address_request(self, params):

        session=self.fortimail_login()
        urladdress= BASE_URL+"ProfSession/{0}/ProfSessionSenderBlacklist/{1}".format(demisto.args().get('Profile_name'),demisto.args().get('Sender_Email_address'))
        demisto.results(session.delete(urladdress,verify=False).json())

        #return self._http_request('DELETE', params, 'ProfSession/{0}/ProfSessionSenderBlacklist/{1}')

    def unblock_recipient_address_request(self, params):

        session.self.fortimail_login()
        urladdress= BASE_URL+"ProfSession/{0}/ProfSessionRecipientBlacklist/{1}".format(demisto.args().get('Profile_name'),demisto.args().get('Recipient_Email_address'))
        demisto.results(session.delete(urladdress,verify=False).json())

        #return self._http_request('DELETE', params, 'ProfSession/{0}/ProfSessionRecipientBlacklist/{1}')

    def display_quarantine_mail_list_request(self):

        session=self.fortimail_login()
        endpoint = "QuarantineMailDisplay"
        req_params = {
            'type': demisto.args().get('type').lower(),
            'folder':  demisto.args().get('folder'),
            'startIndex':  demisto.args().get('start'),
            'pageSize': demisto.args().get('size')
        }
        urladdress = BASE_URL+"QuarantineMailDisplay"
        demisto.results(session.get(urladdress,params=req_params,verify=False).json())
        #return self._http_request("GET", endpoint, req_params)

    def quarantine_release_request(self):

        session = self.fortimail_login()
        endpoint = '{0}'.format(RELEASE_ENDPOINT_MAP.get(demisto.args().get('account_type')))
        payload = {
            'folder': demisto.args().get('folder'),
            'reqAction':  REQ_ACTION,
            'mmkey': handle_multi_value_input(demisto.args().get('message_ids'))
        }
        release_to_others = demisto.args().get('release_to_others')
        if release_to_others:
            payload['otherEmails'] = handle_multi_value_input(demisto.args().get('other_emails'))
        urladdress=BASE_URL+endpoint
        demisto.results(session.post(urladdress,params=payload,verify=False).json())
        #return self._http_request("POST", endpoint, payload)

    def view_mail_in_quarantine_request(self): ############add params

        session=self.fortimail_login()
        req_params = {
            'account_type': ACCOUNT_TYPE_MAP.get(demisto.args().get('account_type')),
            'mfolder': demisto.args().get('folder', ''),
            'account': demisto.args().get('account', '')
        }
        uid_scope = demisto.args().get('uid_scope')
        if uid_scope:
            req_params['uidScope'] = uid_scope
        # session= requests.Session()
        # session.trust_env= False
        urladdress=BASE_URL+'WMMessagesRequest'

        demisto.results(session.post(urladdress,params=req_params,verify=False).json())
        #return self._http_request("POST", "WMMessagesRequest", params=req_params )

    def system_quarantine_batch_release_request(self, folder:str,  start:str, end:str, message_type: str, release_to_original, release_to_others: str, other_emails: list):
        payload = {
            'folder': folder,
            'reqAction':  REQ_ACTION,
            'start': handle_date(start),
            'end': handle_date(end),
            'releaseAll': True if message_type == 'All Messages' else False,
            'releaseToOriginal': release_to_original,
        }
        release_to_others_param = release_to_others
        if release_to_others_param:
            payload['releaseToOthers'] = handle_multi_value_input(other_emails)

        self.fortimail_login()

        return self._http_request("POST", "SystemQuarantineBatchRelease", json_data=json.dumps(payload))


'''Helper Functions'''
def handle_date(str_date):
    return datetime.strptime(str_date, "%Y-%m-%dT%H:%M:%S.%fZ").strftime("%Y-%m-%d")

def handle_multi_value_input(input_data):
    if type(input_data) is list:
        input_data = ','.join(input_data)
    return input_data.replace(' ', '')

def build_params(params, list, map=None):
    try:
        req_params = {}
        if map:
            for i in list:
                if params.get(i):
                    req_params[i] = map[params.get(i)]
        else:
            for i in list:
                if params.get(i) is not None and params.get(i) != "":
                    req_params[i] = params.get(i)
        return req_params
    except Exception as err:
        logger.error(err)
        raise ConnectorError(err)




###########Config###############
def manage_email_address(client: Client, params_profile_name, params_email_address, endpoint, method):
    try:
        profile_name = params_profile_name
        email_address = params_email_address
        endpoint = endpoint.format(profile_name, email_address)
        return _http_request(client, method, endpoint)
    except Exception as e:
        return_error(str(e))

def manage_profile(client: Client, params, endpoint, method):
    try:
        profile_name = params.get("profile_name")
        endpoint = endpoint.format(profile_name)
        return _http_request(client, method, endpoint)
    except Exception as err:
        logger.error(err)
        raise ConnectorError(err)

def manage_list(client: Client, params, list_type):
    try:
        list_items = params.get('items', '')
        payload = {'extraParam': list_type}
        level_type = params.get('level_type')
        payload['reqAction'] = ACTION_MAP.get(params.get('reqAction'))
        payload['listitems'] = ','.join(list_items) if isinstance(list_items, list) else list_items
        level = 'system' if level_type == 'System' else params.get('level')
        resource = params.get('resource')
        endpoint = '/api/v1/{0}/{1}'.format(resource, level)
        return _http_request(client, endpoint, data=payload)
    except Exception as e:
        return_error(str(e))

''' Request Commands'''
def get_domains_command(client: Client, args: Dict[str, Any]):

    return client.get_domains_request(args)

def get_antispam_domains_command(client: Client, args: Dict[str, Any]):

    return client.get_antispam_domains_request(args)

def get_recipient_policies_command(client: Client, args: Dict[str, Any]):

    return client.get_recipient_policies_request(args)

def grey_list_command(client: Client, args: Dict[str, Any]):

    return client.grey_list_request(args)

def get_session_safe_list_command(client: Client, args: Dict[str, Any]):

    return client.get_session_safe_list_request(args)

def get_session_block_list_command(client: Client, args: Dict[str, Any]):

    return client.get_session_block_list_request(args)

def update_block_list_command(client: Client, args: Dict[str, Any]):

    return client.update_block_list_request(args)

def update_safe_list_command(client: Client, args: Dict[str, Any]):

    return client.update_safe_list_request(args)

def block_sender_address_command(client: Client, args: Dict[str, Any]):

    return client.block_sender_address_request()

def block_recipient_address_command(client: Client, args: Dict[str, Any]):

    return client.block_recipient_address_request()

def unblock_sender_address_command(client: Client, args: Dict[str, Any]):

    return client.unblock_sender_address_request()

def unblock_recipient_address_command(client: Client, args: Dict[str, Any]):

    return client.unblock_recipient_address_request()

def display_quarantine_mail_list_command(client: Client, args: Dict[str, Any]):

    return client.display_quarantine_mail_list_request()

def quarantine_release_command(client: Client, args: Dict[str, Any]):

    return client.quarantine_release_request()

def view_mail_in_quarantine_command(client: Client):

    return client.view_mail_in_quarantine_request()

def system_quarantine_batch_release_command(client: Client, args: Dict[str, Any]):

    return client.system_quarantine_batch_release_request(args)

def test_module(client: Client) -> str:
    """
    Validates the correctness of the instance parameters and connectivity to FortiMail API service.
    """
    respose= client.fortimail_login()
    demisto.info("fortimail respose")
    demisto.results(respose)
    #demisto.results(client.fortimail_login())
    return "ok"


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions
    """
    # Commands dictionary
    command = demisto.command()
    commands: Dict[str, Callable] = {
        'get_domains': get_domains_command,
        'get_antispam_domains': get_antispam_domains_command,
        'get_recipient_policies': get_recipient_policies_command,
        'grey_list': grey_list_command,
        'get_session_safe_list': get_session_safe_list_command,
        'get_session_block_list': get_session_block_list_command,
        'update_block_list': update_block_list_command,
        'update_safe_list': update_safe_list_command,
        'block_sender_address': block_sender_address_command,
        'block_recipient_address': block_recipient_address_command,
        'unblock_sender_address': unblock_sender_address_command,
        'unblock_recipient_address': unblock_recipient_address_command,
        'display_quarantine_mail_list': display_quarantine_mail_list_command,
        'quarantine_release': quarantine_release_command,
        'view_mail_in_quarantine': view_mail_in_quarantine_command,
        'system_quarantine_batch_release': system_quarantine_batch_release_command
    }

    demisto.debug(f'[FortiMail] Command being called is {command}')

    params = demisto.params()

    # get the service API url
    base_url = params.get('server')
    #verify_certificate = not params.get('insecure', False)
    verify_certificate = False
    #proxy = params.get('proxy', False)
    proxy = False
    credentials = params.get("credentials", {})
    username = credentials.get('username')
    password = credentials.get('password')

    try:
        client: Client = Client(
            urljoin(base_url, "/api/v1/"),
            username,
            password,
            verify_certificate,
            proxy,
        )

        if command == "test-module":
            return_results(
                test_module(client)
            )
        elif command in commands:
            return_results(commands[command](client))
        else:
            raise NotImplementedError(f"{command} command is not implemented.")

    except Exception as e:
        return_error(str(e))

''' ENTRY POINT '''
if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

register_module_line('FortiMail', 'end', __line__())
