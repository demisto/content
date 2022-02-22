import demistomock as demisto
from IAMInitADUser import main
from typing import Optional, Dict, Tuple, Union

PWD_GENERATION_SCRIPT = 'GeneratePassword'
UNKNOWN_USER = 'Unknown User'
ERROR_5003 = '5003'
ERROR_UNKNOWN_CMD = 'Unknown Command'
MOCK_SAMACCOUNTNAME = 'mock_samaccountname'
MOCK_SAMACCOUNTNAME_BAD_PWD = 'user_with_bad_password'
VALID_SAMACCOUNTNAMES = [MOCK_SAMACCOUNTNAME, MOCK_SAMACCOUNTNAME_BAD_PWD]

MOCK_ARGS = {
    'pwdGenerationScript': PWD_GENERATION_SCRIPT,
    'user_profile': {
        'displayname': 'mock_displayname',
        'email': 'mock_email',
        'manageremailaddress': 'mock_manageremail',
        'acquisitionhire': 'no'
    },
    'sAMAccountName': MOCK_SAMACCOUNTNAME,
    'enable_user': 'true',
    'send_email': 'true',
    'manager_email_template_list_name': 'mock_manager_email_template_list_name',
    'notification_email_addresses': 'mock_notification_email_addresses'
}


def execute_command(cmd: str, args: Optional[Dict] = None,
                    fail_on_error: bool = False) -> Union[Tuple[bool, Optional[str]], Optional[str]]:
    if cmd == 'getList':
        return None  # will use the default email template

    elif cmd == 'GeneratePassword':
        return 'mock_password'

    elif cmd in ['ad-enable-account', 'ad-update-user']:
        return args.get('username') in VALID_SAMACCOUNTNAMES, UNKNOWN_USER

    elif cmd == 'ad-set-new-password':
        if args.get('username') == MOCK_SAMACCOUNTNAME:
            return True, None
        else:  # if args.get('username') == 'user_with_bad_password':
            return False, ERROR_5003

    elif cmd == 'send-mail':
        return args.get('to') is not None, None

    else:
        return False, ERROR_UNKNOWN_CMD


def test_good(mocker):
    mocker.patch.object(demisto, 'args', return_value=MOCK_ARGS)
    mocker.patch('IAMInitADUser.execute_command', side_effect=execute_command)

    main()
    results = demisto.results.call_args[0][0]['Contents']
    assert 


def test_bad_samaccountname(mocker):
    args = MOCK_ARGS.copy()
    args['sAMAccountName'] = 'bad_samaccountname'
    mocker.patch.object(demisto, 'args', return_value=args)

    mocker.patch('IAMInitADUser.execute_command', side_effect=execute_command)


def test_bad_pwd_generation_script(mocker):
    args = MOCK_ARGS.copy()
    args['pwdGenerationScript'] = 'bad_pwdGenerationScript'
    mocker.patch.object(demisto, 'args', return_value=args)

    mocker.patch('IAMInitADUser.execute_command', side_effect=execute_command)


def test_bad_password(mocker):
    args = MOCK_ARGS.copy()
    args['sAMAccountName'] = MOCK_SAMACCOUNTNAME_BAD_PWD
    mocker.patch.object(demisto, 'args', return_value=args)

    mocker.patch('IAMInitADUser.execute_command', side_effect=execute_command)


def test_no_notification_email_addresses(mocker):
    args = MOCK_ARGS.copy()
    del args['notification_email_addresses']
    mocker.patch.object(demisto, 'args', return_value=args)

    mocker.patch('IAMInitADUser.execute_command', side_effect=execute_command)
