import urllib3
import traceback
import demistomock as demisto
from CommonServerPython import *  # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa


# Disable insecure warnings
urllib3.disable_warnings()

''' CLIENT CLASS '''


class Client(BaseClient):
    def live_assign_get(self, analyst_ids, category, created, arg_id, name, severity) -> str:
        params = assign_params(
            analyst_ids=analyst_ids,
            category=category,
            created=created,
            id=arg_id,
            name=name,
            severity=severity
        )
        response = self._http_request(
            method='POST',
            url_suffix='/api/v1/xsoar_live_assign/',
            params=params
        )
        return response['analyst']

    def test(self) -> str:
        response = self._http_request(
            method='GET',
            url_suffix='/api/v1/xsoar_live_assign/'
        )
        return response


''' HELPER FUNCTIONS '''


def get_assignee(client: Client, args) -> CommandResults:
    analyst_ids = argToList(args.get('analyst_ids'))
    category = args.get('category')
    created = args.get('created')
    arg_id = args.get('id')
    name = args.get('name')
    severity = args.get('severity')
    analyst = client.live_assign_get(analyst_ids, category, created, arg_id, name, severity)
    human_readable = tableToMarkdown(
        'Analyst Penfield Recommends',
        analyst,
        headers=['Recommendation'],
        headerTransform=pascalToSpace,
        removeNull=True
    )
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='Penfield.Recommended',
        outputs_key_field='Analyst',
        outputs=analyst
    )


def test_api(client: Client):
    return client.test()


''' MAIN FUNCTION '''


def main() -> None:
    api_key = demisto.params().get('apikey')
    base_url = urljoin(demisto.params()['url'], '')
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        headers = {
            'Authorization': f'Bearer {api_key}'
        }
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy
        )

        if demisto.command() == 'test-module':
            result = test_api(client)
            if int(result) == 0:
                return_results('ok')
            else:
                raise RuntimeError('Penfield API cannot be reached')

        elif demisto.command() == 'penfield-get-assignee':
            result = get_assignee(client, demisto.args())
            return_results(result)

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(
            f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}'
        )


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
