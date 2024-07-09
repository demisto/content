import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' CONSTANTS '''
API_ENDPOINT = 'https://driftapi.com'


class Client(BaseClient):

    def test(self):
        url_suffix = '/users/list'
        self._http_request('GET', url_suffix=url_suffix)

    def post_contact(self, email: dict = None):
        url_suffix = '/contacts'
        res = self._http_request('POST', url_suffix=url_suffix, json_data=email)
        return res

    def get_contact(self, contact_id: str = None, email: str = None):
        url_suffix = '/contacts'
        params = {}
        if contact_id:
            url_suffix = f"{url_suffix}/{contact_id}"
        elif email:
            params['email'] = email
        res = self._http_request(
            'GET',
            url_suffix=url_suffix,
            params=params
        )
        return res.get('data', [])

    def patch_contact(self, contact_id: str = None, attributes: dict = None):
        url_suffix = f"/contacts/{contact_id}"
        res = self._http_request(
            'PATCH',
            url_suffix=url_suffix,
            json_data=attributes
        )
        return res

    def delete_contact(self, contact_id: str = None):
        url_suffix = f"/contacts/{contact_id}"
        res = self._http_request(
            'DELETE',
            url_suffix=url_suffix,
            resp_type='response',
            ok_codes=[200, 202])
        return res


def test_module(client: Client):
    client.test()
    return_results('ok')


def post_contact_command(client, args):
    email = {
        'attributes': {
            'email': args.get('email')
        }
    }
    res = client.post_contact(email=email)
    command_results = CommandResults(
        outputs_prefix='Drift.Contacts',
        outputs_key_field=['id'],
        outputs=res,
        readable_output=tableToMarkdown('Contact:', res)
    )
    return command_results


def get_contact_command(client, args):
    email = args.get('email')
    contact_id = args.get('id')
    if not email and not contact_id:
        return_error("Please provide one of the ID or Email")
    res = client.get_contact(email=email, contact_id=contact_id)
    command_results = CommandResults(
        outputs_prefix='Drift.Contacts',
        outputs_key_field=['id'],
        outputs=res,
        readable_output=tableToMarkdown('Contact:', res)
    )
    return_results(command_results)


def patch_contact_command(client, args):
    contact_id = args.get('id')
    attributes = {
        'attributes': args.get('attributes')
    }
    res = client.patch_contact(contact_id=contact_id, attributes=attributes)
    command_results = CommandResults(
        outputs_prefix='Drift.Contacts',
        outputs_key_field=['id'],
        outputs=res,
        readable_output=tableToMarkdown('Contact:', res)
    )
    return_results(command_results)


def delete_contact_command(client, args):
    contact_id = args.get('id')
    client.delete_contact(contact_id=contact_id)
    command_results = CommandResults(
        readable_output=f"Contact ID {contact_id} was deleted."
    )
    return_results(command_results)


def main():
    params = demisto.params()
    args = demisto.args()
    credentials = params.get('access_token')
    access_token = credentials.get('password')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    command = demisto.command()

    commands = {
        'drift-post-contact': post_contact_command,
        'drift-get-contact': get_contact_command,
        'drift-update-contact': patch_contact_command,
        'drift-delete-contact': delete_contact_command
    }

    demisto.debug(f'Command being called is {command}')
    try:
        headers = {
            'Authorization': f'Bearer {access_token}'
        }
        client = Client(
            API_ENDPOINT,
            verify_certificate,
            proxy,
            headers=headers
        )

        if command == 'test-module':
            test_module(client)
        elif command in commands:
            commands[command](client, args)

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {command} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
