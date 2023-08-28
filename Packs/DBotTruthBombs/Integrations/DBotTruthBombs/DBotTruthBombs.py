import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import random
import traceback

import urllib3

# Disable insecure warnings
urllib3.disable_warnings()


BASE_URL = 'https://api.chucknorris.io'

CATEGORIES = ['career', 'dev', 'history', 'money', 'movie', 'music', 'science', 'sport', 'travel']

CHUCK_NORRIS_NAMES = [
    'Chuck Norris',
    'ChuckNorris',
    'chuck norris',
    'Chuck norris',
]

DBOT_NAME = 'DBot'


def replace_to_user_name(joke) -> str:
    res = joke
    for name in CHUCK_NORRIS_NAMES:
        res = res.replace(name, DBOT_NAME)
    return res


class Client(BaseClient):
    def chuck_norris_random(self, category) -> Dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix='/jokes/random',
            params={
                'category': category
            }
        )


def test_module(client: Client) -> str:
    dbot_fact(client, {})
    return 'ok'


def get_dbot_image_path() -> str:
    image_index = random.randint(1, 16)

    return 'https://raw.githubusercontent.com/demisto/content/9784db67bb70839f1122ff5753d66cefbe2ca0d1/' \
           f'Packs/DBotTruthBombs/doc_imgs/dbot{image_index}.png'


def get_readable_output(fact, image) -> str:
    return f'### {fact}\n![DBot Image]({image})'


def dbot_fact(client: Client, args: Dict[str, Any]) -> Any:
    category = args.get('category', random.choice(CATEGORIES)).lower()
    result = client.chuck_norris_random(category)
    value = result.get('value')

    fact = replace_to_user_name(value)
    image = get_dbot_image_path()

    return CommandResults(
        readable_output=get_readable_output(fact, image),
        raw_response={
            "fact": fact,
            "image": image
        }
    )


def main() -> None:
    params = demisto.params()
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    try:
        verify_certificate = not params.get('insecure', False)
        proxy = params.get('proxy', False)

        client = Client(
            base_url=BASE_URL,
            verify=verify_certificate,
            proxy=proxy)

        if command == 'test-module':
            result = test_module(client)
            return_results(result)

        elif command == 'dbot-truth-bomb':
            return_results(dbot_fact(client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
