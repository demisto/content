import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import traceback
from typing import Any


DBOT_NAME = 'DBot'


def dbot_fact(category) -> dict[str, Any]:
    args = {}
    if category:
        args['category'] = category
    res = demisto.executeCommand('dbot-truth-bomb', args)

    if isError(res[0]):
        return_error('Error getting dbot truth bomb - {}'.format(res[0]['Contents']))

    return res[0]['Contents']


def get_current_user() -> str:
    current_user_res = demisto.executeCommand("getUsers", {
        'current': True
    })

    if isError(current_user_res[0]):
        return_error('Error getting current user - {}'.format(current_user_res[0]['Contents']))

    users = current_user_res[0]['Contents']
    if len(users) == 0:
        return_error('Could not find current user')

    return users[0]


def replace_to_user_name(fact, user) -> str:
    current_user_name = user.get('name', user.get('username'))

    res = fact.replace(DBOT_NAME, current_user_name)
    return res


def get_readable_output(fact, image) -> str:
    return f'### {fact}\n![Image]({image})'


def get_user_fact(args: dict[str, Any]) -> CommandResults:
    category = args.get('category')

    res = dbot_fact(category)

    user = get_current_user()
    fact = replace_to_user_name(res["fact"], user)
    image = res["image"]
    return CommandResults(
        readable_output=get_readable_output(fact, image)
    )


def main():
    try:
        return_results(get_user_fact(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute Script. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
