import json

import urllib3
from CommonServerPython import *


urllib3.disable_warnings()


class Client(BaseClient):

    def get_transactionlog(self, page, search, locked) -> Dict[str, Any]:
        if page is None:
            page = 1

        p_search = ""
        if search is not None and search != '':
            p_search = '&search=%s' % search

        p_locked = ""
        if locked is not None and locked:
            p_locked = '&locked=%s' % "true"

        return self._http_request(
            method='GET',
            url_suffix='/transactionlog/?page=%s%s%s' % (page, p_search, p_locked),
            resp_type='text'
        )

    def get_users(self, page, search, locked) -> Dict[str, Any]:
        if page is None:
            page = 1

        p_search = ""
        if search is not None and search != '':
            p_search = '&search=%s' % search

        p_locked = ""
        if locked is not None and locked:
            p_locked = '&locked=%s' % "true"

        return self._http_request(
            method='GET',
            url_suffix='/userlist/?page=%s%s%s' % (page, p_search, p_locked),
            resp_type='text'
        )

    def get_ldap_users(self, page, search, locked, ldap) -> Dict[str, Any]:
        if page is None:
            page = 1

        p_search = ""
        if search is not None and search != '':
            p_search = '&search=%s' % search

        p_locked = ""
        if locked is not None and locked:
            p_locked = '&locked=%s' % "true"

        return self._http_request(
            method='GET',
            url_suffix='/userlist/%s/?page=%s%s%s' % (ldap, page, p_search, p_locked),
            resp_type='text'
        )

    def get_ldaps(self) -> Dict[str, Any]:
        return json.loads(self._http_request(
            method='GET',
            url_suffix='/ldapconfiguration/',
            resp_type='text'
        ))

    def get_user_personalinformation(self, username) -> Dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix='/user/%s/' % username,
            resp_type='text'
        )

    def set_user_personalinformation(self, username, email, mobile_phone) -> Dict[str, Any]:
        post_params = {}
        if email:
            post_params['email'] = email
        if mobile_phone:
            post_params['mobile_phone'] = mobile_phone

        return self._http_request(
            method='PUT',
            url_suffix='/user/%s/' % username,
            json_data=post_params,
            resp_type='text'
        )

    def get_user_accessattempts(self, username) -> Dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix='/user/%s/access_attempt/' % username,
            resp_type='text'
        )

    def delete_user_accessattempts(self, username) -> Dict[str, Any]:
        return self._http_request(
            method='DELETE',
            url_suffix='/user/%s/access_attempt/' % username,
            resp_type='text'
        )

    # Get "params" to generalize all token types.
    # Said argument must be a dictionary or json with the data corresponding to the token to be registered
    def create_user_token(self, username, post_params) -> Dict[str, Any]:
        return self._http_request(
            method='POST',
            url_suffix='/user/%s/devices/' % username,
            json_data=post_params,
            resp_type='text'
        )

    def update_user_token(self, username, token_devicetype, token_serialnumber, post_params) -> Dict[str, Any]:
        return self._http_request(
            method='PUT',
            url_suffix='/user/%s/devices/%s/%s/' % (username, token_devicetype, token_serialnumber),
            json_data=post_params,
            resp_type='text'
        )

    def get_user_tokens(self, username) -> Dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix='/user/%s/devices/' % username,
            resp_type='text'
        )

    def delete_user_token(self, username, token_devicetype, token_serialnumber) -> Dict[str, Any]:
        return self._http_request(
            method='DELETE',
            url_suffix='/user/%s/devices/%s/%s/' % (username, token_devicetype, token_serialnumber),
            resp_type='text'
        )

    def send_user_token(self, username, token_devicetype, token_serialnumber) -> Dict[str, Any]:
        return self._http_request(
            method='POST',
            url_suffix='/user/%s/devices/%s/%s/send/' % (username, token_devicetype, token_serialnumber),
            resp_type='text'
        )

    def send_user_virtualtoken(self, username, token_devicetype, token_serialnumber) -> Dict[str, Any]:
        return self._http_request(
            method='POST',
            url_suffix='/devices/%s/%s/code/' % (token_devicetype, token_serialnumber),
            resp_type='text'
        )

    def get_user_settings(self, username) -> Dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix='/user/%s/settings/' % username,
            resp_type='text'
        )

    # Get "params" to generalize all configuration items.
    # This argument must be a dictionary or json with the items that you want to modify
    def set_user_settings(self, username, post_params) -> Dict[str, Any]:
        return self._http_request(
            method='PATCH',
            url_suffix='/user/%s/settings/' % username,
            json_data=post_params,
            resp_type='text'
        )

    def get_user_group(self, username) -> Dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix='/user/%s/group/' % username,
            resp_type='text'
        )

    def add_user_group(self, username, new_group_name) -> Dict[str, Any]:
        post_params = {'username': username}

        return self._http_request(
            method='POST',
            url_suffix='/group/%s/member/' % new_group_name,
            json_data=post_params,
            resp_type='text'
        )

    def remove_user_group(self, username, old_group_name) -> Dict[str, Any]:
        return self._http_request(
            method='DELETE',
            url_suffix='/group/%s/member/%s/' % (old_group_name, username),
            resp_type='text'
        )

    def get_user_registrationcode(self, username) -> Dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix='/user/%s/registrationtoken/' % username,
            resp_type='text'
        )

    def set_user_registrationcode(self, username, expiration, attempts_left) -> Dict[str, Any]:

        post_params = {
            'username': username,
            'expiration': expiration,
            'attempts_left': attempts_left,
            'sent_on': '',
            'sent_by': '',
            'token': ''
        }

        return self._http_request(
            method='POST',
            url_suffix='/user/%s/registrationtoken/' % username,
            json_data=post_params,
            resp_type='text'
        )

    def delete_user_registrationcode(self, username) -> Dict[str, Any]:
        return self._http_request(
            method='DELETE',
            url_suffix='/user/%s/registrationtoken/' % username,
            resp_type='text'
        )

    def send_user_registrationcode(self, username) -> Dict[str, Any]:
        return self._http_request(
            method='POST',
            url_suffix='/user/%s/registrationtoken/send/' % username,
            resp_type='text'
        )

    def create_user(self, username, password, firstname, lastname, mobilephone, email):

        post_params = {'username': username, 'password': password, 'first_name': firstname,
                       'last_name': lastname, 'mobile_phone': mobilephone, 'email': email}

        return self._http_request(
            method='POST',
            url_suffix='/user/',
            json_data=post_params,
            resp_type='text'
        )

    def delete_user(self, username):
        return self._http_request(
            method='DELETE',
            url_suffix='/user/%s/' % username,
            resp_type='text'
        )


def get_transactionlog(client, args):
    page = args.get('page')
    search = args.get('search')
    locked = args.get('locked')

    result_raw = client.get_transactionlog(page, search, locked)
    if result_raw:
        result_raw = json.loads(result_raw)
        result = remove_empty_elements(result_raw)
    else:
        result = {}
    readable_output = tableToMarkdown(
        'Get Transaction Log Results',
        result,
        headers=list(result.keys()),
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='GetTransactionLog.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result_raw
    )

    return command_results


def get_users(client, args):
    page = args.get('page')
    search = args.get('search')
    locked = args.get('locked')

    result_raw = client.get_users(page, search, locked)
    if result_raw:
        result_raw = json.loads(result_raw)
        result = remove_empty_elements(result_raw)
    else:
        result = {}
    readable_output = tableToMarkdown(
        'Get User Results',
        result,
        headers=list(result.keys()),
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='GetUsers.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result_raw
    )

    return command_results


def get_ldap_users(client, args):
    page = args.get('page')
    search = args.get('search')
    locked = args.get('locked')
    ldap = args.get('ldap')

    result_raw = client.get_ldap_users(page, search, locked, ldap)
    if result_raw:
        result_raw = json.loads(result_raw)
        result = remove_empty_elements(result_raw)
    else:
        result = {}
    readable_output = tableToMarkdown(
        'Get Ldap users Results',
        result,
        headers=list(result.keys()),
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='GetLdapUsers.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result_raw
    )

    return command_results


def get_ldaps(client, args):
    result_raw = client.get_ldaps()
    if result_raw:
        result_raw = json.loads(result_raw)
        result = remove_empty_elements(result_raw)
    else:
        result = {}
    readable_output = tableToMarkdown(
        'Get Ldaps Results',
        result,
        headers=list(result.keys()),
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='GetLdaps.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result_raw
    )

    return command_results


def get_user_personalinformation(client, args):
    username = args.get('username')

    result_raw = client.get_user_personalinformation(username)
    if result_raw:
        result_raw = json.loads(result_raw)
        result = remove_empty_elements(result_raw)
    else:
        result = {}
    readable_output = tableToMarkdown(
        'Get User Personal Information Results',
        result,
        headers=list(result.keys()),
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='GetUserPersonalInformation.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result_raw
    )

    return command_results


def set_user_personalinformation(client, args):
    username = args.get('username')
    email = args.get('email')
    mobile_phone = args.get('mobile_phone')

    result_raw = client.set_user_personalinformation(username, email, mobile_phone)
    if result_raw:
        result_raw = json.loads(result_raw)
        result = remove_empty_elements(result_raw)
    else:
        result = {}
    readable_output = tableToMarkdown(
        'Set User Personal Information Results',
        result,
        headers=list(result.keys()),
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='SetUserPersonalInformation.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result_raw
    )

    return command_results


def get_user_accessattempts(client, args):
    username = args.get('username')

    result_raw = client.get_user_accessattempts(username)
    if result_raw:
        result_raw = json.loads(result_raw)
        result = remove_empty_elements(result_raw)
    else:
        result = {}
    readable_output = tableToMarkdown(
        'Get User Access Attempts Results',
        result,
        headers=list(result.keys()),
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='GetUserAccessAttempts.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result_raw
    )

    return command_results


def delete_user_accessattempts(client, args):
    username = args.get('username')

    result_raw = client.delete_user_accessattempts(username)
    if result_raw:
        result_raw = json.loads(result_raw)
        result = remove_empty_elements(result_raw)
    else:
        result = {}
    readable_output = tableToMarkdown(
        'Delete User Access Attempts Results',
        result,
        headers=list(result.keys()),
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='DeleteUserAccessAttempts.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result_raw
    )

    return command_results


def create_user_token_virtual(client, args):

    username = args.get('username')
    post_params = {
        'device_type': 'Virtual'
    }

    result_raw = client.create_user_token(username, post_params)
    if result_raw:
        result_raw = json.loads(result_raw)
        result = remove_empty_elements(result_raw)
    else:
        result = {}
    readable_output = tableToMarkdown(
        'Create User Token Virtual Results',
        result,
        headers=list(result.keys()),
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='CreateUserTokenVirtual.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result_raw
    )

    return command_results


def create_user_token_fastauth(client, args):

    username = args.get('username')
    post_params = {
        'device_type': 'Fast:Auth:Mobile:Asymmetric',
        'serial_number': args.get('serial-number'),
        'password_required': ''
    }

    result_raw = client.create_user_token(username, post_params)
    if result_raw:
        result_raw = json.loads(result_raw)
        result = remove_empty_elements(result_raw)
    else:
        result = {}
    readable_output = tableToMarkdown(
        'Create User Token Fast Auth Results',
        result,
        headers=list(result.keys()),
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='CreateUserTokenFastAuth.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result_raw
    )

    return command_results


def create_user_token_totpmobile(client, args):

    username = args.get('username')
    post_params = {
        'device_type': 'TOTP:Mobile',
        'serial_number': args.get('serial-number'),
        'password_required': args.get('password-required')
    }

    result_raw = client.create_user_token(username, post_params)
    if result_raw:
        result_raw = json.loads(result_raw)
        result = remove_empty_elements(result_raw)
    else:
        result = {}
    readable_output = tableToMarkdown(
        'Create User Token Totp Mobile Results',
        result,
        headers=list(result.keys()),
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='CreateUserTokenTotpMobile.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result_raw
    )

    return command_results


def create_user_token_totmobilehybrid(client, args):

    username = args.get('username')
    post_params = {
        'device_type': 'TOTP:Mobile:Hybrid',
        'serial_number': args.get('serial-number'),
        'password_required': ''
    }

    result_raw = client.create_user_token(username, post_params)
    if result_raw:
        result_raw = json.loads(result_raw)
        result = remove_empty_elements(result_raw)
    else:
        result = {}
    readable_output = tableToMarkdown(
        'Create User Token Tot Mobile Hybrid Results',
        result,
        headers=list(result.keys()),
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='CreateUserTokenTotMobileHybrid.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result_raw
    )

    return command_results


def create_user_token_physical(client, args):

    username = args.get('username')
    post_params = {
        'device_type': args.get('devicetype'),
        'serial_number': args.get('serial-number'),
        'password_required': args.get('password-required')
    }

    result_raw = client.create_user_token(username, post_params)
    if result_raw:
        result_raw = json.loads(result_raw)
        result = remove_empty_elements(result_raw)
    else:
        result = {}
    readable_output = tableToMarkdown(
        'Create User Token Physical Results',
        result,
        headers=list(result.keys()),
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='CreateUserTokenPhysical.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result_raw
    )

    return command_results


def create_user_token_backup(client, args):

    username = args.get('username')
    post_params = {
        'device_type': 'Backup',
        'serial_number': '',
        'password_required': args.get('password-required'),
        'backuptoken_timeout': args.get('backuptoken-timeout'),
        'backuptoken_attempts': args.get('backuptoken_attempts'),
        'backuptoken_gateways': ''
    }

    result_raw = client.create_user_token(username, post_params)
    if result_raw:
        result_raw = json.loads(result_raw)
        result = remove_empty_elements(result_raw)
    else:
        result = {}
    readable_output = tableToMarkdown(
        'Create User Token Backup Results',
        result,
        headers=list(result.keys()),
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='CreateUserTokenBackup.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result_raw
    )

    return command_results


# See
def update_user_token(client, args):
    username = args.get('username')
    token_devicetype = args.get('devicetype')
    token_serialnumber = args.get('serialnumber')
    post_params = args.get('params')

    result_raw = client.update_user_token(username, token_devicetype, token_serialnumber, post_params)
    if result_raw:
        result_raw = json.loads(result_raw)
        result = remove_empty_elements(result_raw)
    else:
        result = {}
    readable_output = tableToMarkdown(
        'Update User Token Results',
        result,
        headers=list(result.keys()),
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='UpdateUserToken.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result_raw
    )

    return command_results


def get_user_tokens(client, args):
    username = args.get('username')

    result_raw = client.get_user_tokens(username)
    if result_raw:
        result_raw = json.loads(result_raw)
        result = remove_empty_elements(result_raw)
    else:
        result = {}
    readable_output = tableToMarkdown(
        'Get User Tokens Results',
        result,
        headers=list(result.keys()),
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='GetUserTokens.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result_raw
    )

    return command_results


def delete_user_token(client, args):
    username = args.get('username')
    token_devicetype = args.get('devicetype')
    token_serialnumber = args.get('serialnumber')

    result_raw = client.delete_user_token(username, token_devicetype, token_serialnumber)
    if result_raw:
        result_raw = json.loads(result_raw)
        result = remove_empty_elements(result_raw)
    else:
        result = {}
    readable_output = tableToMarkdown(
        'Delete User Token Results',
        result,
        headers=list(result.keys()),
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='DeleteUserToken.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result_raw
    )

    return command_results


def send_user_token(client, args):
    username = args.get('username')
    token_devicetype = args.get('devicetype')
    token_serialnumber = args.get('serialnumber')

    result_raw = client.send_user_token(username, token_devicetype, token_serialnumber)
    if result_raw:
        result_raw = json.loads(result_raw)
        result = remove_empty_elements(result_raw)
    else:
        result = {}
    readable_output = tableToMarkdown(
        'Send User Token Results',
        result,
        headers=list(result.keys()),
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='SendUserToken.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result_raw
    )

    return command_results


def send_user_virtualtoken(client, args):
    username = args.get('username')
    token_devicetype = args.get('devicetype')
    token_serialnumber = args.get('serialnumber')

    result_raw = client.send_user_virtualtoken(username, token_devicetype, token_serialnumber)
    if result_raw:
        result_raw = json.loads(result_raw)
        result = remove_empty_elements(result_raw)
    else:
        result = {}
    readable_output = tableToMarkdown(
        'Send User Virtual Token Results',
        result,
        headers=list(result.keys()),
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='SendUserVirtualToken.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result_raw
    )

    return command_results


def get_user_settings(client, args):
    username = args.get('username')

    result_raw = client.get_user_settings(username)
    if result_raw:
        result_raw = json.loads(result_raw)
        result = remove_empty_elements(result_raw)
    else:
        result = {}
    readable_output = tableToMarkdown(
        'Get User Settings Results',
        result,
        headers=list(result.keys()),
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='GetUserSettings.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result_raw
    )

    return command_results


def set_user_backuptoken_settings(client, args):
    username = args.get('username')
    backup_password_required = args.get('backup-password-required')
    backuptoken_attempts = args.get('backuptoken-attempts')
    backuptoken_timeout = args.get('backuptoken-timeout')

    params = {}

    if not backup_password_required:
        params['backup_password_required'] = backup_password_required

    if not backuptoken_attempts:
        params['backuptoken_attempts'] = backuptoken_attempts

    if not backuptoken_timeout:
        params['backuptoken_timeout'] = backuptoken_timeout

    result_raw = client.set_user_settings(username, params)
    if result_raw:
        result_raw = json.loads(result_raw)
        result = remove_empty_elements(result_raw)
    else:
        result = {}
    readable_output = tableToMarkdown(
        'Set User Backup Token Settings Results',
        result,
        headers=list(result.keys()),
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='SetUserBackupTokenSettings.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result_raw
    )

    return command_results


def set_user_general_settings(client, args):
    username = args.get('username')
    user_storage = args.get('user-storage')

    params = {}

    if not user_storage:
        params['user_storage'] = user_storage

    result_raw = client.set_user_settings(username, params)
    if result_raw:
        result_raw = json.loads(result_raw)
        result = remove_empty_elements(result_raw)
    else:
        result = {}
    readable_output = tableToMarkdown(
        'Set User General Settings Results',
        result,
        headers=list(result.keys()),
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='SetUserGeneralSettings.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result_raw
    )

    return command_results


def set_user_hotpauthentication_settings(client, args):
    username = args.get('username')
    hotp_accept_tolerance = args.get('hotp-accept-tolerance')
    hotp_resend_tolerance = args.get('hotp-resend-tolerance')
    hotp_resend_timeout = args.get('hotp-resend-timeout')
    hotp_password_required = args.get('hotp-password_required')
    hotp_flex_password_required = args.get('hotp-flex-password-required')
    hotp_flex_pin_password_required = args.get('hotp-flex-pin-password-required')

    params = {}

    if not hotp_accept_tolerance:
        params['hotp_accept_tolerance'] = hotp_accept_tolerance

    if not hotp_resend_tolerance:
        params['hotp_resend_tolerance'] = hotp_resend_tolerance

    if not hotp_resend_timeout:
        params['hotp_resend_timeout'] = hotp_resend_timeout

    if not hotp_password_required:
        params['hotp_password_required'] = hotp_password_required

    if not hotp_flex_password_required:
        params['hotp_flex_password_required'] = hotp_flex_password_required

    if not hotp_flex_pin_password_required:
        params['hotp_flex_pin_password_required'] = hotp_flex_pin_password_required

    result_raw = client.set_user_settings(username, params)

    if result_raw:
        result_raw = json.loads(result_raw)
        result = remove_empty_elements(result_raw)
    else:
        result = {}

    readable_output = tableToMarkdown(
        'Set User Hotp Authentication Settings Results',
        result,
        headers=list(result.keys()),
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='SetUserHotpAuthenticationSettings.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result_raw
    )

    return command_results


def set_user_sesamiauthentication_settings(client, args):
    username = args.get('username')
    sesami_mobile_password_required = args.get('sesami_mobile_password_required')
    sesami_slim_password_required = args.get('sesami_slim_password_required')
    gaia_ttw_level = args.get('gaia_ttw_level')

    params = {}

    if not sesami_mobile_password_required:
        params['sesami_mobile_password_required'] = sesami_mobile_password_required

    if not sesami_slim_password_required:
        params['sesami_slim_password_required'] = sesami_slim_password_required

    if not gaia_ttw_level:
        params['gaia_ttw_level'] = gaia_ttw_level

    result_raw = client.set_user_settings(username, params)
    if result_raw:
        result_raw = json.loads(result_raw)
        result = remove_empty_elements(result_raw)
    else:
        result = {}
    readable_output = tableToMarkdown(
        'Set User Sesami Authentication Settings Results',
        result,
        headers=list(result.keys()),
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='SetUserSesamiAuthenticationSettings.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result_raw
    )

    return command_results


def set_user_totpauthentication_settings(client, args):
    username = args.get('username')
    totp_accept_tolerance = args.get('totp-accept-tolerance')
    totp_resend_tolerance = args.get('totp-resend-tolerance')
    totp_resend_timeout = args.get('totp-resend-timeout')
    totp_password_required = args.get('totp-password-required')
    totp_flex_password_required = args.get('totp-flex-password-required')
    totp_flex_pin_password_required = args.get('totp-flex-pin-password-required')
    totp_mobile_password_required = args.get('totp-mobile-password-required')

    params = {}

    if not totp_accept_tolerance:
        params['totp_accept_tolerance'] = totp_accept_tolerance

    if not totp_resend_tolerance:
        params['totp_resend_tolerance'] = totp_resend_tolerance

    if not totp_resend_timeout:
        params['totp_resend_timeout'] = totp_resend_timeout

    if not totp_password_required:
        params['totp_password_required'] = totp_password_required

    if not totp_flex_password_required:
        params['totp_flex_password_required'] = totp_flex_password_required

    if not totp_flex_pin_password_required:
        params['totp_flex_pin_password_required'] = totp_flex_pin_password_required

    if not totp_mobile_password_required:
        params['totp_mobile_password_required'] = totp_mobile_password_required

    result_raw = client.set_user_settings(username, params)
    if result_raw:
        result_raw = json.loads(result_raw)
        result = remove_empty_elements(result_raw)
    else:
        result = {}
    readable_output = tableToMarkdown(
        'Set User Totp Authentication Settings Results',
        result,
        headers=list(result.keys()),
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='SetUserTotpAuthenticationSettings.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result_raw
    )

    return command_results


def set_user_userauthentication_settings(client, args):
    username = args.get('username')
    multiple_step_auth_timeout = args.get('multiple-step-auth-timeout')
    allow_password = args.get('allow-password')
    allow_password_for_registration = args.get('allow-password-for-registration')
    max_allowed_failures = args.get('max-allowed-failures')
    allow_access_when_pwd_expired = args.get('allow-access-when-pwd-expired')
    allow_password_reset_when_forgot_pwd = args.get('allow-password-reset-when-forgot-pwd')
    min_otp_length = args.get('min-otp-length')
    max_otp_length = args.get('max-otp-length')
    dos_tmp_lockdown_max_fail_authentications = args.get('dos-tmp-lockdown-max-fail-authentications')
    dos_tmp_lockdown_time_interval_in_seconds = args.get('dos-tmp-lockdown-time-interval-in-seconds')
    dos_tmp_lockdown_time_in_seconds = args.get('dos-tmp-lockdown-time-in-seconds')

    params = {}

    if not multiple_step_auth_timeout:
        params['multiple_step_auth_timeout'] = multiple_step_auth_timeout

    if not allow_password:
        params['allow_password'] = allow_password

    if not allow_password_for_registration:
        params['allow_password_for_registration'] = allow_password_for_registration

    if not max_allowed_failures:
        params['max_allowed_failures'] = max_allowed_failures

    if not allow_access_when_pwd_expired:
        params['allow_access_when_pwd_expired'] = allow_access_when_pwd_expired

    if not allow_password_reset_when_forgot_pwd:
        params['allow_password_reset_when_forgot_pwd'] = allow_password_reset_when_forgot_pwd

    if not min_otp_length:
        params['min_otp_length'] = min_otp_length

    if not max_otp_length:
        params['max_otp_length'] = max_otp_length

    if not dos_tmp_lockdown_max_fail_authentications:
        params['dos_tmp_lockdown_max_fail_authentications'] = dos_tmp_lockdown_max_fail_authentications

    if not dos_tmp_lockdown_time_interval_in_seconds:
        params['dos_tmp_lockdown_time_interval_in_seconds'] = dos_tmp_lockdown_time_interval_in_seconds

    if not dos_tmp_lockdown_time_in_seconds:
        params['dos_tmp_lockdown_time_in_seconds'] = dos_tmp_lockdown_time_in_seconds

    result_raw = client.set_user_settings(username, params)
    if result_raw:
        result_raw = json.loads(result_raw)
        result = remove_empty_elements(result_raw)
    else:
        result = {}
    readable_output = tableToMarkdown(
        'Set User User Authentication Settings Results',
        result,
        headers=list(result.keys()),
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='SetUserUserAuthenticationSettings.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result_raw
    )

    return command_results


def set_user_virtualauthentication_settings(client, args):
    username = args.get('username')
    virtual_device_accept_tolerance = args.get('virtual-device-accept-tolerance')
    virtual_device_gateways = args.get('virtual-device-gateways')

    params = {}

    if not virtual_device_accept_tolerance:
        params['virtual_device_accept_tolerance'] = virtual_device_accept_tolerance

    if not virtual_device_gateways:
        params['virtual_device_gateways'] = virtual_device_gateways

    result_raw = client.set_user_settings(username, params)
    if result_raw:
        result_raw = json.loads(result_raw)
        result = remove_empty_elements(result_raw)
    else:
        result = {}
    readable_output = tableToMarkdown(
        'Set User Virtual Authentication Settings Results',
        result,
        headers=list(result.keys()),
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='SetUserVirtualAuthenticationSettings.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result_raw
    )

    return command_results


def get_user_group(client, args):
    username = args.get('username')

    result_raw = client.get_user_group(username)
    if result_raw:
        result_raw = json.loads(result_raw)
        result = remove_empty_elements(result_raw)
    else:
        result = {}
    readable_output = tableToMarkdown(
        'Get User Group Results',
        result,
        headers=list(result.keys()),
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='GetUserGroup.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result_raw
    )

    return command_results


def update_user_group(client, args):
    username = args.get('username')
    new_group_name = args.get('new-group-name')

    result_raw = client.get_user_group(username)

    old_group_name = None
    for group in result_raw.get("groups"):
        if bool(group.get("is_member")):
            old_group_name = group.get("name")

    if old_group_name and new_group_name:
        client.remove_user_group(username, old_group_name)
        client.add_user_group(username, new_group_name)

    result = {'message': 'Successfully updated'}
    if result_raw:
        result_raw = json.loads(result_raw)
        result = remove_empty_elements(result_raw)
    else:
        result = {}
    readable_output = tableToMarkdown(
        'Update User Group Results',
        result,
        headers=list(result.keys()),
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='UpdateUserGroup.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result_raw
    )

    return command_results


def add_user_group(client, args):
    username = args.get('username')
    new_group_name = args.get('new-group-name')

    result_raw = client.add_user_group(username, new_group_name)
    if result_raw:
        result_raw = json.loads(result_raw)
        result = remove_empty_elements(result_raw)
    else:
        result = {}
    readable_output = tableToMarkdown(
        'Add User Group Results',
        result,
        headers=list(result.keys()),
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='AddUserGroup.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result_raw
    )

    return command_results


def remove_user_group(client, args):
    username = args.get('username')
    old_group_name = args.get('old-group-name')

    result_raw = client.remove_user_group(username, old_group_name)
    if result_raw:
        result_raw = json.loads(result_raw)
        result = remove_empty_elements(result_raw)
    else:
        result = {}
    readable_output = tableToMarkdown(
        'Remove User Group Results',
        result,
        headers=list(result.keys()),
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='RemoveUserGroup.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result_raw
    )

    return command_results


def get_user_registrationcode(client, args):
    username = args.get('username')

    result_raw = client.get_user_registrationcode(username)
    if result_raw:
        result_raw = json.loads(result_raw)
        result = remove_empty_elements(result_raw)
    else:
        result = {}
    readable_output = tableToMarkdown(
        'Get User Registration Code Results',
        result,
        headers=list(result.keys()),
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='GetUserRegistrationCode.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result_raw
    )

    return command_results


def set_user_registrationcode(client, args):
    username = args.get('username')

    expiration = args.get('expiration')
    attempts_left = args.get('attempts-left')

    result_raw = client.set_user_registrationcode(username, expiration, attempts_left)
    if result_raw:
        result_raw = json.loads(result_raw)
        result = remove_empty_elements(result_raw)
    else:
        result = {}
    readable_output = tableToMarkdown(
        'Set User Registration Code Results',
        result,
        headers=list(result.keys()),
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='SetUserRegistrationCode.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result_raw
    )

    return command_results


def delete_user_registrationcode(client, args):
    username = args.get('username')

    result_raw = client.delete_user_registrationcode(username)
    if result_raw:
        result_raw = json.loads(result_raw)
        result = remove_empty_elements(result_raw)
    else:
        result = {}
    readable_output = tableToMarkdown(
        'Delete User Registration Code Results',
        result,
        headers=list(result.keys()),
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='DeleteUserRegistrationCode.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result_raw
    )

    return command_results


def send_user_registrationcode(client, args):
    username = args.get('username')

    result_raw = client.send_user_registrationcode(username)
    if result_raw:
        result_raw = json.loads(result_raw)
        result = remove_empty_elements(result_raw)
    else:
        result = {}
    readable_output = tableToMarkdown(
        'Send User Registration Code Results',
        result,
        headers=list(result.keys()),
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='SendUserRegistrationCode.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result_raw
    )

    return command_results


def create_user(client, args):
    username = args.get('username')
    password = args.get('password')
    firstname = args.get('firstname')
    lastname = args.get('lastname')
    mobilephone = args.get('mobilephone')
    email = args.get('email')

    result_raw = client.create_user(username, password, firstname, lastname, mobilephone, email)
    if result_raw:
        result_raw = json.loads(result_raw)
        result = remove_empty_elements(result_raw)
    else:
        result = {}

    readable_output = tableToMarkdown(
        'Create User Results',
        result,
        headers=list(result.keys()),
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='CreateUser.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result_raw
    )

    return command_results


def delete_user(client, args):
    username = args.get('username')

    result_raw = client.delete_user(username)
    if result_raw:
        result_raw = json.loads(result_raw)
        result = remove_empty_elements(result_raw)
    else:
        result = {}

    readable_output = tableToMarkdown(
        'Delete User Results',
        result,
        headers=list(result.keys()),
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='DeleteUser.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result_raw
    )

    return command_results


def test_module(client):
    results = client.get_transactionlog(None, None, None)

    if results:
        results = json.loads(results).get('results')
        if results and len(results) > 0:
            if results[0].get('reason_detail') == 'Invalid credentials':
                return 'Failed to run test, invalid credentials.'
            else:
                return 'ok'
    else:
        return 'Failed to run test.'


def main():

    params = demisto.params()
    command = demisto.command()
    args = demisto.args()
    base_url = params.get('url')
    base_url = base_url + '/api/v1/admin/'
    demisto.info('BASE_URL' + base_url)
    verify_certificate = not params.get('insecure', False)
    auth_access_token = params.get('apikey')
    proxy = params.get('proxy', False)
    demisto.debug(f'Command being called is {command}')
    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers={'Authorization': 'Bearer %s' % auth_access_token},
            proxy=proxy)

        if command == 'safewalk-get-transactionlog':
            result = get_transactionlog(client, args)
            return_results(result)

        if command == 'safewalk-get-users':
            result = get_users(client, args)
            return_results(result)

        if command == 'safewalk-get-ldap-users':
            result = get_ldap_users(client, args)
            return_results(result)

        if command == 'safewalk-get-ldaps':
            result = get_ldaps(client, args)
            return_results(result)

        if command == 'safewalk-get-user-personalinformation':
            result = get_user_personalinformation(client, args)
            return_results(result)

        if command == 'safewalk-set-user-personalinformation':
            result = set_user_personalinformation(client, args)
            return_results(result)

        if command == 'safewalk-get-user-accessattempts':
            result = get_user_accessattempts(client, args)
            return_results(result)

        if command == 'safewalk-delete-user-accessattempts':
            result = delete_user_accessattempts(client, args)
            return_results(result)

        if command == 'safewalk-create-user-token-virtual':
            result = create_user_token_virtual(client, args)
            return_results(result)

        if command == 'safewalk-create-user-token-fastauth':
            result = create_user_token_fastauth(client, args)
            return_results(result)

        if command == 'safewalk-create-user-token-totpmobile':
            result = create_user_token_totpmobile(client, args)
            return_results(result)

        if command == 'safewalk-create-user-token-totmobilehybrid':
            result = create_user_token_totmobilehybrid(client, args)
            return_results(result)

        if command == 'safewalk-create-user-token-physical':
            result = create_user_token_physical(client, args)
            return_results(result)

        if command == 'safewalk-create-user-token-backup':
            result = create_user_token_backup(client, args)
            return_results(result)

        if command == 'safewalk-update-user-token':
            result = update_user_token(client, args)
            return_results(result)

        if command == 'safewalk-get-user-tokens':
            result = get_user_tokens(client, args)
            return_results(result)

        if command == 'safewalk-delete-user-token':
            result = delete_user_token(client, args)
            return_results(result)

        if command == 'safewalk-send-user-token':
            result = send_user_token(client, args)
            return_results(result)

        if command == 'safewalk-send-user-virtualtoken':
            result = send_user_virtualtoken(client, args)
            return_results(result)

        if command == 'safewalk-get-user-settings':
            result = get_user_settings(client, args)
            return_results(result)

        if command == 'safewalk-set-user-backuptoken-settings':
            result = set_user_backuptoken_settings(client, args)
            return_results(result)

        if command == 'safewalk-set-user-general-settings':
            result = set_user_general_settings(client, args)
            return_results(result)

        if command == 'safewalk-set-user-hotpauthentication-settings':
            result = set_user_hotpauthentication_settings(client, args)
            return_results(result)

        if command == 'safewalk-set-user-sesamiauthentication-settings':
            result = set_user_sesamiauthentication_settings(client, args)
            return_results(result)

        if command == 'safewalk-set-user-totpauthentication-settings':
            result = set_user_totpauthentication_settings(client, args)
            return_results(result)

        if command == 'safewalk-set-user-userauthentication-settings':
            result = set_user_userauthentication_settings(client, args)
            return_results(result)

        if command == 'safewalk-set-user-virtualauthentication-settings':
            result = set_user_virtualauthentication_settings(client, args)
            return_results(result)

        if command == 'safewalk-get-user-group':
            result = get_user_group(client, args)
            return_results(result)

        if command == 'safewalk-update-user-group':
            result = update_user_group(client, args)
            return_results(result)

        if command == 'safewalk-add-user-group':
            result = add_user_group(client, args)
            return_results(result)

        if command == 'safewalk-remove-user-group':
            result = remove_user_group(client, args)
            return_results(result)

        if command == 'safewalk-get-user-registrationcode':
            result = get_user_registrationcode(client, args)
            return_results(result)

        if command == 'safewalk-set-user-registrationcode':
            result = set_user_registrationcode(client, args)
            return_results(result)

        if command == 'safewalk-delete-user-registrationcode':
            result = delete_user_registrationcode(client, args)
            return_results(result)

        if command == 'safewalk-send-user-registrationcode':
            result = send_user_registrationcode(client, args)
            return_results(result)

        if command == 'safewalk-create-user':
            result = create_user(client, args)
            return_results(result)

        if command == 'safewalk-delete-user':
            result = delete_user(client, args)
            return_results(result)

        if command == 'test-module':
            result = test_module(client)
            return_results(result)

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {command} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
