import traceback
from typing import Any, Dict

import demistomock as demisto
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]

# COMMAND FUNCTION #


def validate_token(token):
    if token.lower() != 'the auto extract feature':
        raise ValueError('Unsupported indicator. Try another one...')


def set_user_credentials(indicator_id):
    res = demisto.executeCommand('setIndicator', {
        'id': indicator_id,
        'customFields': {
            'logininfo': 'Go to Tier2 tenant',
            'username': 'Isaac',
            'usercredentials': '![Reveal Password](https://raw.githubusercontent.com/demisto/content/'
                               'EscapeRoomMaterials/Packs/EscapeRoomTier1/images/indicator_QR.png)',
        },
    })

    if is_error(res):
        demisto.error(f'oh no!\n{res}\n\n')
        raise RuntimeError('failed to update hint, check logs for more info.')


def reputation_command(args: Dict[str, Any]) -> CommandResults:
    token = args.get('token', '')
    indicator_id = args.get('indicator_id', '')

    demisto.info(f'token: {token}\t indicator ID: {indicator_id}')

    validate_token(token)
    set_user_credentials(indicator_id)

    return CommandResults(
        readable_output=' ',
    )


# MAIN FUNCTION #


def main():
    try:
        return_results(reputation_command(demisto.args()))
    except Exception as exc:  # pylint: disable=W0703
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute ERTokenReputation. Error: {str(exc)}')


# ENTRY POINT #


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
