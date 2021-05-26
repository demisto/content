import urllib3
import json
from typing import Any, Dict



urllib3.disable_warnings()



DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
MAX_INCIDENTS_TO_FETCH = 50
HELLOWORLD_SEVERITIES = ['Low', 'Medium', 'High', 'Critical']



class Client(BaseClient):

    def get_transactionlog(self, page, search, locked) -> Dict[str, Any]:
        if page is None:
            page = 1

        p_search=""
        if search is not None and search != '':
            p_search = '&search=%s' % search

        p_locked = ""
        if locked is not None and locked:
            p_locked = '&locked=%s' % "true"

        return self._http_request(
            method='GET',
            url_suffix='/transactionlog/?page=%s%s%s' % (page, p_search, p_locked),
            resp_type = 'text'
        )

    def get_users(self, page, search, locked) -> Dict[str, Any]:
        if page is None:
            page = 1

        p_search=""
        if search is not None and search != '':
            p_search = '&search=%s' % search

        p_locked = ""
        if locked is not None and locked:
            p_locked = '&locked=%s' % "true"

        return self._http_request(
            method='GET',
            url_suffix='/userlist/?page=%s%s%s' % (page, p_search, p_locked),
            resp_type = 'text'
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
            resp_type = 'text'
        )

    def get_ldaps(self) -> Dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix='/ldapconfiguration/',
            resp_type = 'text'
        )

    def get_user_personalinformation(self, username) -> Dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix='/user/%s/'% username,
            resp_type = 'text'
        )

    def set_user_personalinformation(self, username, email, mobile_phone) -> Dict[str, Any]:
        post_params = {}
        if email:
            post_params['email'] = email
        if mobile_phone:
            post_params['mobile_phone'] = mobile_phone

        return self._http_request(
            method='PUT',
            url_suffix='/user/%s/'% username,
            json_data=post_params,
            resp_type = 'text'
        )

    def get_user_accessattempts(self, username) -> Dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix='/user/%s/access_attempt/' % username,
            resp_type = 'text'
        )

    def delete_user_accessattempts(self, username) -> Dict[str, Any]:
        return self._http_request(
            method='DELETE',
            url_suffix='/user/%s/access_attempt/' % username,
            resp_type = 'text'
        )

    #Get "params" to generalize all token types. Said argument must be a dictionary or json with the data corresponding to the token to be registered
    def create_user_token(self, username, post_params) -> Dict[str, Any]:
        return self._http_request(
            method='POST',
            url_suffix='/user/%s/devices/' % username,
            json_data=post_params,
            resp_type = 'text'
        )

    def update_user_token(self, username, token_devicetype, token_serialnumber, post_params) -> Dict[str, Any]:
        return self._http_request(
            method='PUT',
            url_suffix='/user/%s/devices/%s/%s/' % (username, token_devicetype, token_serialnumber),
            json_data=post_params,
            resp_type = 'text'
        )

    def get_user_tokens(self, username) -> Dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix='/user/%s/devices/' % username,
            resp_type = 'text'
        )

    def delete_user_token(self, username, token_devicetype, token_serialnumber) -> Dict[str, Any]:
        return self._http_request(
            method='DELETE',
            url_suffix='/user/%s/devices/%s/%s/' % (username, token_devicetype, token_serialnumber),
            resp_type = 'text'
        )

    def send_user_token(self, username, token_devicetype, token_serialnumber) -> Dict[str, Any]:
        return self._http_request(
            method='POST',
            url_suffix='/user/%s/devices/%s/%s/send/' % (username, token_devicetype, token_serialnumber),
            resp_type = 'text'
        )

    def send_user_virtualtoken(self, username, token_devicetype, token_serialnumber) -> Dict[str, Any]:
        return self._http_request(
            method='POST',
            url_suffix='/devices/<device_type>/<serial_number>/code/' % (token_devicetype, token_serialnumber),
            resp_type = 'text'
        )

    def get_user_settings(self, username) -> Dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix='/user/%s/settings/' % username,
            resp_type = 'text'
        )

    #Get "params" to generalize all configuration items. This argument must be a dictionary or json with the items that you want to modify
    def set_user_settings(self, username, post_params) -> Dict[str, Any]:
        return self._http_request(
            method='PATCH',
            url_suffix='/user/%s/settings/' % username,
            json_data=post_params,
            resp_type = 'text'
        )

    def get_user_group(self, username) -> Dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix='/user/%s/group/' % username,
            resp_type = 'text'
        )

    def add_user_group(self, username, new_group_name) -> Dict[str, Any]:
        post_params = {'username':username}

        return self._http_request(
            method='POST',
            url_suffix='/group/%s/member/' % new_group_name,
            json_data=post_params,
            resp_type = 'text'
        )

    def remove_user_group(self, username, old_group_name) -> Dict[str, Any]:
        return self._http_request(
            method='DELETE',
            url_suffix='/group/%s/member/%s/' % (old_group_name, username),
            resp_type = 'text'
        )

    def get_user_registrationcode(self, username) -> Dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix='/user/%s/registrationtoken/' % username,
            resp_type = 'text'
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
            resp_type = 'text'
        )

    def delete_user_registrationcode(self, username) -> Dict[str, Any]:
        return self._http_request(
            method='DELETE',
            url_suffix='/user/%s/registrationtoken/' % username,
            resp_type = 'text'
        )

    def send_user_registrationcode(self, username) -> Dict[str, Any]:
        return self._http_request(
            method='POST',
            url_suffix='/user/%s/registrationtoken/send/' % username,
            resp_type = 'text'
        )

    def create_user(self, username, password, firstname, lastname, mobilephone, email):

        post_params = {'username':username, 'password':password, 'first_name':firstname, 'last_name':lastname, 'mobile_phone':mobilephone, 'email':email}

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

    result = client.get_transactionlog(page, search, locked)

    readable_output = f'## {result}'

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='GetTransactionLog.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result
    )

    return command_results

def get_users(client, args):
    page = args.get('page')
    search = args.get('search')
    locked = args.get('locked')

    result = client.get_users(page, search, locked)

    readable_output = f'## {result}'

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='GetUsers.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result
    )

    return command_results

def get_ldap_users(client, args):
    page = args.get('page')
    search = args.get('search')
    locked = args.get('locked')
    ldap = args.get('ldap')

    result = client.get_ldap_users(page, search, locked, ldap)

    readable_output = f'## {result}'

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='GetLdapUsers.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result
    )

    return command_results

def get_ldaps(client, args):
    result = client.get_ldaps()

    readable_output = f'## {result}'

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='GetLdaps.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result
    )

    return command_results

def get_user_personalinformation(client, args):
    username = args.get('username')

    result = client.get_user_personalinformation(username)

    readable_output = f'## {result}'

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='GetUserPersonalInformation.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result
    )

    return command_results

def set_user_personalinformation(client, args):
    username = args.get('username')
    email = args.get('email')
    mobile_phone = args.get('mobile_phone')

    result = client.set_user_personalinformation(username, email, mobile_phone)

    readable_output = f'## {result}'

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='SetUserPersonalInformation.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result
    )

    return command_results

def get_user_accessattempts(client, args):
    username = args.get('username')

    result = client.get_user_accessattempts(username)

    readable_output = f'## {result}'

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='GetUserAccessAttempts.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result
    )

    return command_results

def delete_user_accessattempts(client, args):
    username = args.get('username')

    result = client.delete_user_accessattempts(username)

    readable_output = f'## {result}'

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='DeleteUserAccessAttempts.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result
    )

    return command_results

def create_user_token_virtual(client, args):

    username = args.get('username')
    post_params = {
        'device_type': 'Virtual'
    }

    result = client.create_user_token(username, post_params)

    readable_output = f'## {result}'

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='CreateUserTokenVirtual.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result
    )

    return command_results

def create_user_token_fastauth(client, args):

    username = args.get('username')
    post_params = {
        'device_type': 'Fast:Auth:Mobile:Asymmetric',
        'serial_number': args.get('serial-number'),
        'password_required': ''
    }

    result = client.create_user_token(username, post_params)

    readable_output = f'## {result}'

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='CreateUserTokenFastAuth.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result
    )

    return command_results

def create_user_token_totpmobile(client, args):

    username = args.get('username')
    post_params = {
        'device_type': 'TOTP:Mobile',
        'serial_number': args.get('serial-number'),
        'password_required': args.get('password-required')
    }

    result = client.create_user_token(username, post_params)

    readable_output = f'## {result}'

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='CreateUserTokenTotpMobile.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result
    )

    return command_results

def create_user_token_totmobilehybrid(client, args):

    username = args.get('username')
    post_params = {
        'device_type': 'TOTP:Mobile:Hybrid',
        'serial_number': args.get('serial-number'),
        'password_required': ''
    }

    result = client.create_user_token(username, post_params)

    readable_output = f'## {result}'

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='CreateUserTokenTotMobileHybrid.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result
    )

    return command_results

def create_user_token_physical(client, args):

    username = args.get('username')
    post_params = {
        'device_type': args.get('devicetype'),
        'serial_number': args.get('serial-number'),
        'password_required': args.get('password-required')
    }

    result = client.create_user_token(username, post_params)

    readable_output = f'## {result}'

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='CreateUserTokenPhysical.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result
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

    result = client.create_user_token(username, post_params)

    readable_output = f'## {result}'

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='CreateUserTokenBackup.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result
    )

    return command_results

#See
def update_user_token(client, args):
    username = args.get('username')
    token_devicetype = args.get('devicetype')
    token_serialnumber = args.get('serialnumber')
    post_params = args.get('params')

    result = client.update_user_token(username, token_devicetype, token_serialnumber, post_params)

    readable_output = f'## {result}'

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='UpdateUserToken.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result
    )

    return command_results

def get_user_tokens(client, args):
    username = args.get('username')

    result = client.get_user_tokens(username)

    readable_output = f'## {result}'

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='GetUserTokens.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result
    )

    return command_results

def delete_user_token(client, args):
    username = args.get('username')
    token_devicetype = args.get('devicetype')
    token_serialnumber = args.get('serialnumber')

    result = client.delete_user_token(username, token_devicetype, token_serialnumber)

    readable_output = f'## {result}'

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='DeleteUserToken.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result
    )

    return command_results

def send_user_token(client, args):
    username = args.get('username')
    token_devicetype = args.get('devicetype')
    token_serialnumber = args.get('serialnumber')

    result = client.send_user_token(username, token_devicetype, token_serialnumber)

    readable_output = f'## {result}'

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='SendUserToken.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result
    )

    return command_results

def send_user_virtualtoken(client, args):
    username = args.get('username')
    token_devicetype = args.get('devicetype')
    token_serialnumber = args.get('serialnumber')

    result = client.send_user_virtualtoken(username, token_devicetype, token_serialnumber)

    readable_output = f'## {result}'

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='SendUserVirtualToken.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result
    )

    return command_results

def get_user_settings(client, args):
    username = args.get('username')

    result = client.get_user_settings(username)

    readable_output = f'## {result}'

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='GetUserSettings.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result
    )

    return command_results

def set_user_backuptoken_settings(client, args):
    username = args.get('username')
    backup_password_required = args.get('backup-password-required')
    backuptoken_attempts = args.get('backuptoken-attempts')
    backuptoken_timeout = args.get('backuptoken-timeout')

    params = {}

    if backup_password_required != None:
        params['backup_password_required'] = backup_password_required

    if backuptoken_attempts != None:
        params['backuptoken_attempts'] = backuptoken_attempts

    if backuptoken_timeout != None:
        params['backuptoken_timeout'] = backuptoken_timeout


    result = client.set_user_settings(username, params)

    readable_output = f'## {result}'

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='SetUserBackupTokenSettings.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result
    )

    return command_results


def set_user_general_settings(client, args):
    username = args.get('username')
    user_storage = args.get('user-storage')

    params = {}

    if user_storage != None:
        params['user_storage'] = user_storage


    result = client.set_user_settings(username, params)

    readable_output = f'## {result}'

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='SetUserGeneralSettings.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result
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

    if hotp_accept_tolerance != None:
        params['hotp_accept_tolerance'] = hotp_accept_tolerance

    if hotp_resend_tolerance != None:
        params['hotp_resend_tolerance'] = hotp_resend_tolerance

    if hotp_resend_timeout != None:
        params['hotp_resend_timeout'] = hotp_resend_timeout

    if hotp_password_required != None:
        params['hotp_password_required'] = hotp_password_required

    if hotp_flex_password_required != None:
        params['hotp_flex_password_required'] = hotp_flex_password_required

    if hotp_flex_pin_password_required != None:
        params['hotp_flex_pin_password_required'] = hotp_flex_pin_password_required


    result = client.set_user_settings(username, params)

    readable_output = f'## {result}'

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='SetUserHotpAuthenticationSettings.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result
    )

    return command_results

def set_user_sesamiauthentication_settings(client, args):
    username = args.get('username')
    sesami_mobile_password_required = args.get('sesami_mobile_password_required')
    sesami_slim_password_required = args.get('sesami_slim_password_required')
    gaia_ttw_level = args.get('gaia_ttw_level')

    params = {}

    if sesami_mobile_password_required != None:
        params['sesami_mobile_password_required'] = sesami_mobile_password_required

    if sesami_slim_password_required != None:
        params['sesami_slim_password_required'] = sesami_slim_password_required

    if gaia_ttw_level != None:
        params['gaia_ttw_level'] = gaia_ttw_level


    result = client.set_user_settings(username, params)

    readable_output = f'## {result}'

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='SetUserSesamiAuthenticationSettings.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result
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

    if totp_accept_tolerance != None:
        params['totp_accept_tolerance'] = totp_accept_tolerance

    if totp_resend_tolerance != None:
        params['totp_resend_tolerance'] = totp_resend_tolerance

    if totp_resend_timeout != None:
        params['totp_resend_timeout'] = totp_resend_timeout

    if totp_password_required != None:
        params['totp_password_required'] = totp_password_required

    if totp_flex_password_required != None:
        params['totp_flex_password_required'] = totp_flex_password_required

    if totp_flex_pin_password_required != None:
        params['totp_flex_pin_password_required'] = totp_flex_pin_password_required

    if totp_mobile_password_required != None:
        params['totp_mobile_password_required'] = totp_mobile_password_required


    result = client.set_user_settings(username, params)

    readable_output = f'## {result}'

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='SetUserTotpAuthenticatioSettings.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result
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

    if multiple_step_auth_timeout != None:
        params['multiple_step_auth_timeout'] = multiple_step_auth_timeout

    if allow_password != None:
        params['allow_password'] = allow_password

    if allow_password_for_registration != None:
        params['allow_password_for_registration'] = allow_password_for_registration

    if max_allowed_failures != None:
        params['max_allowed_failures'] = max_allowed_failures

    if allow_access_when_pwd_expired != None:
        params['allow_access_when_pwd_expired'] = allow_access_when_pwd_expired

    if allow_password_reset_when_forgot_pwd != None:
        params['allow_password_reset_when_forgot_pwd'] = allow_password_reset_when_forgot_pwd

    if min_otp_length != None:
        params['min_otp_length'] = min_otp_length

    if max_otp_length != None:
        params['max_otp_length'] = max_otp_length

    if dos_tmp_lockdown_max_fail_authentications != None:
        params['dos_tmp_lockdown_max_fail_authentications'] = dos_tmp_lockdown_max_fail_authentications

    if dos_tmp_lockdown_time_interval_in_seconds != None:
        params['dos_tmp_lockdown_time_interval_in_seconds'] = dos_tmp_lockdown_time_interval_in_seconds

    if dos_tmp_lockdown_time_in_seconds != None:
        params['dos_tmp_lockdown_time_in_seconds'] = dos_tmp_lockdown_time_in_seconds


    result = client.set_user_settings(username, params)

    readable_output = f'## {result}'

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='SetUserUserAuthenticationSettings.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result
    )

    return command_results

def set_user_virtualauthentication_settings(client, args):
    username = args.get('username')
    virtual_device_accept_tolerance = args.get('virtual-device-accept-tolerance')
    virtual_device_gateways = args.get('virtual-device-gateways')

    params = {}

    if virtual_device_accept_tolerance != None:
        params['virtual_device_accept_tolerance'] = virtual_device_accept_tolerance

    if virtual_device_gateways != None:
        params['virtual_device_gateways'] = virtual_device_gateways


    result = client.set_user_settings(username, params)

    readable_output = f'## {result}'

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='SetUserVirtualAuthenticationSettings.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result
    )

    return command_results

def get_user_group(client, args):
    username = args.get('username')

    result = client.get_user_group(username)

    readable_output = f'## {result}'

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='GetUserGroup.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result
    )

    return command_results

def update_user_group(client, args):
    username = args.get('username')
    new_group_name = args.get('new-group-name')

    result = client.get_user_group(username)

    result_json = json.loads(result)
    old_group_name = None
    for group in result_json["groups"]:
        if group["is_member"] == True:
            old_group_name = group["name"]

    if old_group_name and new_group_name:
        client.remove_user_group(username, old_group_name)
        client.add_user_group(username, new_group_name)


def add_user_group(client, args):
    username = args.get('username')
    new_group_name = args.get('new-group-name')

    result = client.add_user_group(username, new_group_name)

    readable_output = f'## {result}'

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='AddUserGroup.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result
    )

    return command_results

def remove_user_group(client, args):
    username = args.get('username')
    old_group_name = args.get('old-group-name')

    result = client.remove_user_group(username, old_group_name)

    readable_output = f'## {result}'

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='RemoveUserGroup.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result
    )

    return command_results

def get_user_registrationcode(client, args):
    username = args.get('username')

    result = client.get_user_registrationcode(username)

    readable_output = f'## {result}'

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='GetUserRegistrationCode.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result
    )

    return command_results

def set_user_registrationcode(client, args):
    username = args.get('username')

    expiration = args.get('expiration')
    attempts_left = args.get('attempts-left')

    result = client.set_user_registrationcode(username, expiration, attempts_left)

    readable_output = f'## {result}'

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='SetUserRegistrationCode.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result
    )

    return command_results

def delete_user_registrationcode(client, args):
    username = args.get('username')

    result = client.delete_user_registrationcode(username)

    readable_output = f'## {result}'

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='DeleteUserRegistrationCode.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result
    )

    return command_results

def send_user_registrationcode(client, args):
    username = args.get('username')

    result = client.send_user_registrationcode(username)

    readable_output = f'## {result}'

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='SendUserRegistrationCode.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result
    )

    return command_results


def create_user(client, args):
    username = args.get('username')
    password = args.get('password')
    firstname = args.get('firstname')
    lastname = args.get('lastname')
    mobilephone = args.get('mobilephone')
    email = args.get('email')

    result = client.create_user(username, password, firstname, lastname, mobilephone, email)

    readable_output = f'## {result}'

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='CreateUser.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result
    )

    return command_results


def delete_user(client, args):
    username = args.get('username')

    result = client.delete_user(username)

    readable_output = f'## {result}'

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='DeleteUser.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result
    )

    return command_results


def test_module(client, args):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.
    Args:
        client: HelloWorld client
    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    args
    uri = 'users/me'
    client._http_request(method='GET', url_suffix=uri)
    return 'ok', None, None


def main():

    base_url = demisto.params()['url']
    base_url = base_url + '/api/v1/admin/'
    demisto.info('BASE_URL' + base_url)
    verify_certificate = not demisto.params().get('insecure', False)
    auth_access_token = demisto.params()['apikey']
    proxy = demisto.params().get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers={'Authorization': 'Bearer %s' % auth_access_token},
            proxy=proxy)

        if demisto.command() == 'safewalk-get-transactionlog':
            result = get_transactionlog(client, demisto.args())
            return_results(result)

        if demisto.command() == 'safewalk-get-users':
            result = get_users(client, demisto.args())
            return_results(result)

        if demisto.command() == 'safewalk-get-ldap-users':
            result = get_ldap_users(client, demisto.args())
            return_results(result)

        if demisto.command() == 'safewalk-get-ldaps':
            result = get_ldaps(client, demisto.args())
            return_results(result)

        if demisto.command() == 'safewalk-get-user-personalinformation':
            result = get_user_personalinformation(client, demisto.args())
            return_results(result)

        if demisto.command() == 'safewalk-set-user-personalinformation':
            result = set_user_personalinformation(client, demisto.args())
            return_results(result)

        if demisto.command() == 'safewalk-get-user-accessattempts':
            result = get_user_accessattempts(client, demisto.args())
            return_results(result)

        if demisto.command() == 'safewalk-delete-user-accessattempts':
            result = delete_user_accessattempts(client, demisto.args())
            return_results(result)

        if demisto.command() == 'safewalk-create-user-token-virtual':
            result = create_user_token_virtual(client, demisto.args())
            return_results(result)

        if demisto.command() == 'safewalk-create-user-token-fastauth':
            result = create_user_token_fastauth(client, demisto.args())
            return_results(result)

        if demisto.command() == 'safewalk-create-user-token-totpmobile':
            result = create_user_token_totpmobile(client, demisto.args())
            return_results(result)

        if demisto.command() == 'safewalk-create-user-token-totmobilehybrid':
            result = create_user_token_totmobilehybrid(client, demisto.args())
            return_results(result)

        if demisto.command() == 'safewalk-create-user-token-physical':
            result = create_user_token_physical(client, demisto.args())
            return_results(result)

        if demisto.command() == 'safewalk-create-user-token-backup':
            result = create_user_token_backup(client, demisto.args())
            return_results(result)

        if demisto.command() == 'safewalk-update-user-token':
            result = update_user_token(client, demisto.args())
            return_results(result)

        if demisto.command() == 'safewalk-get-user-tokens':
            result = get_user_tokens(client, demisto.args())
            return_results(result)

        if demisto.command() == 'safewalk-delete-user-token':
            result = delete_user_token(client, demisto.args())
            return_results(result)

        if demisto.command() == 'safewalk-send-user-token':
            result = send_user_token(client, demisto.args())
            return_results(result)

        if demisto.command() == 'safewalk-send-user-virtualtoken':
            result = send_user_virtualtoken(client, demisto.args())
            return_results(result)

        if demisto.command() == 'safewalk-get-user-settings':
            result = get_user_settings(client, demisto.args())
            return_results(result)

        if demisto.command() == 'safewalk-set-user-backuptoken-settings':
            result = set_user_backuptoken_settings(client, demisto.args())
            return_results(result)

        if demisto.command() == 'safewalk-set-user-general-settings':
            result = set_user_general_settings(client, demisto.args())
            return_results(result)

        if demisto.command() == 'safewalk-set-user-hotpauthentication-settings':
            result = set_user_hotpauthentication_settings(client, demisto.args())
            return_results(result)

        if demisto.command() == 'safewalk-set-user-sesamiauthentication-settings':
            result = set_user_sesamiauthentication_settings(client, demisto.args())
            return_results(result)

        if demisto.command() == 'safewalk-set-user-totpauthentication-settings':
            result = set_user_totpauthentication_settings(client, demisto.args())
            return_results(result)

        if demisto.command() == 'safewalk-set-user-userauthentication-settings':
            result = set_user_userauthentication_settings(client, demisto.args())
            return_results(result)

        if demisto.command() == 'safewalk-set-user-virtualauthentication-settings':
            result = set_user_virtualauthentication_settings(client, demisto.args())
            return_results(result)

        if demisto.command() == 'safewalk-get-user-group':
            result = get_user_group(client, demisto.args())
            return_results(result)

        if demisto.command() == 'safewalk-update-user-group':
            result = update_user_group(client, demisto.args())
            return_results(result)

        if demisto.command() == 'safewalk-add-user-group':
            result = add_user_group(client, demisto.args())
            return_results(result)

        if demisto.command() == 'safewalk-remove-user-group':
            result = remove_user_group(client, demisto.args())
            return_results(result)

        if demisto.command() == 'safewalk-get-user-registrationcode':
            result = get_user_registrationcode(client, demisto.args())
            return_results(result)

        if demisto.command() == 'safewalk-set-user-registrationcode':
            result = set_user_registrationcode(client, demisto.args())
            return_results(result)

        if demisto.command() == 'safewalk-delete-user-registrationcode':
            result = delete_user_registrationcode(client, demisto.args())
            return_results(result)

        if demisto.command() == 'safewalk-send-user-registrationcode':
            result = send_user_registrationcode(client, demisto.args())
            return_results(result)

        if demisto.command() == 'safewalk-create-user':
            result = create_user(client, demisto.args())
            return_results(result)

        if demisto.command() == 'safewalk-delete-user':
            result = delete_user(client, demisto.args())
            return_results(result)

        if demisto.command() == 'test-module':
            result = test_module(client, demisto.args())
            return_results(result)

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')



if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
