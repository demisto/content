''' IMPORTS '''
from __future__ import print_function
import MimecastV2

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

policy_args = policy_data.copy()
del policy_args['option']
del policy_args['policy_id']
get_args_response = (policy_args, 'no_action', 'IDFROMMIMECAST')

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

update_policy_args = {'fromType': 'free_mail_domains', 'description': 'new new', 'policy_id': 'IDFROMMIMECAST'}
update_policy_req_response = {
    'policy': policy_obj,
    'option': 'no_action',
    'id': 'IDFROMMIMECAST'
}


def get_arguments_for_policy_command():
    res = MimecastV2.get_arguments_for_policy_command('update', policy_data)
    assert get_args_response == res


def test_update_policy(mocker):
    mocker.patch.object(MimecastV2, 'get_arguments_for_policy_command', return_value=get_args_response)
    mocker.patch.object(MimecastV2, 'update_policy_request', return_value=update_policy_req_response)
    res = MimecastV2.update_policy(update_policy_args)
    assert res['Contents']['Description'] == 'new new'
    assert res['Contents']['Sender']['Type'] == 'free_mail_domains'
