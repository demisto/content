''' IMPORTS '''
from __future__ import print_function
import MimecastV2
from CommonServerPython import *


# Parameters for Get arguments test
policy_data = {
    'description': 'new',
    'fromPart': 'bla bla',
    'fromType': 'free_mail_domains',
    'fromValue': 'gmail.com',
    'toType': 'email_domain',
    'toValue': 'gmail.com',
    'option': 'no_action',
    'policy_id': 'IDFROMMIMECAST'
}

policy_args = {
    'description': 'new',
    'fromPart': 'bla bla',
    'fromType': 'free_mail_domains',
    'fromValue': 'gmail.com',
    'toType': 'email_domain',
    'toValue': 'gmail.com'
}

get_args_response = (policy_args, 'no_action')

# Parameters for Update policy test
policy_obj = {
    'description': 'new new',
    'from': {
        'emailDomain': 'gmail.com',
        'type': 'free_mail_domains'
    },
    'to': {
        'emailDomain': 'gmail.com',
        'type': 'email_domain'
    }
}

update_two_args = {'fromType': 'free_mail_domains', 'description': 'new new'}
update_all_args = {'fromType': 'free_mail_domains', 'fromValue': 'gmail.com', 'toType': 'email_domain',
                   'toValue': 'gmail.com', 'description': 'new new'}
update_policy_req_response = {
    'policy': policy_obj,
    'option': 'no_action',
    'id': 'IDFROMMIMECAST'
}

set_empty_value_args_res_list = [update_two_args, 'no_action', 'IDFROMMIMECAST']
set_empty_value_args_res_list_all = [update_all_args, 'no_action', 'IDFROMMIMECAST']
demisto_args = {'policy_id': 'IDFROMMIMECAST'}


def test_get_arguments_for_policy_command():
    res = MimecastV2.get_arguments_for_policy_command(policy_data)
    assert get_args_response == res


def test_update_policy(mocker):
    mocker.patch.object(MimecastV2, 'get_arguments_for_policy_command', return_value=get_args_response)
    mocker.patch.object(MimecastV2, 'set_empty_value_args_policy_update', return_value=set_empty_value_args_res_list)
    mocker.patch.object(MimecastV2, 'create_or_update_policy_request', return_value=update_policy_req_response)
    mocker.patch.object(demisto, 'args', return_value=demisto_args)

    res = MimecastV2.update_policy()
    assert res['Contents']['Description'] == 'new new'
    assert res['Contents']['Sender']['Type'] == 'free_mail_domains'

    mocker.patch.object(MimecastV2, 'get_arguments_for_policy_command', return_value=get_args_response)
    mocker.patch.object(MimecastV2, 'set_empty_value_args_policy_update', return_value=set_empty_value_args_res_list_all)
    mocker.patch.object(MimecastV2, 'create_or_update_policy_request', return_value=update_policy_req_response)
    mocker.patch.object(demisto, 'args', return_value=demisto_args)
    res = MimecastV2.update_policy()
    assert res['Contents']['Description'] == 'new new'
    assert res['Contents']['Sender']['Type'] == 'free_mail_domains'
    assert res['Contents']['Sender']['Domain'] == 'gmail.com'
    assert res['Contents']['Receiver']['Type'] == 'email_domain'
    assert res['Contents']['Receiver']['Domain'] == 'gmail.com'
