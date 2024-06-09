import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # pragma: no cover


def main():
    res = demisto.executeCommand('addEntitlement', {
                                 'persistent': demisto.get(demisto.args(), 'persistent'),
                                 'replyEntriesTag': demisto.get(demisto.args(), 'replyEntriesTag')})

    if isError(res[0]):
        demisto.results(res)
        sys.exit(0)
    entitlement = demisto.get(res[0], 'Contents')

    option1 = demisto.get(demisto.args(), 'option1')

    if not option1:
        option1 = 'yes'
    option2 = demisto.get(demisto.args(), 'option2')

    if not option2:
        option2 = 'no'
    entitlementString = entitlement + '@' + demisto.investigation()['id']

    args = demisto.args()
    lifetime = args.get('lifetime', '1 day')
    try:
        parsed_date = arg_to_datetime('in ' + lifetime)
        assert parsed_date is not None, f'Could not parse in {lifetime}'
        expiry = datetime.strftime(parsed_date, DATE_FORMAT)
    except Exception:
        demisto.debug(f'Could not parse the argument "lifetime" , got {lifetime}. will use "in 1 day" instead')
        parsed_date = arg_to_datetime('in 1 day')
        assert parsed_date is not None
        expiry = datetime.strftime(parsed_date,
                                   DATE_FORMAT)
    default_response = args.get('default_response')
    reply = args.get('reply')

    if task := demisto.get(args, 'task'):
        entitlementString += '|' + task

    message = f'**{args.get("message")}** - Please reply to this thread with `{option1}` or `{option2}`.'

    message_dict = json.dumps({
        'message': message,
        'entitlement': entitlementString,
        'reply': reply,
        'expiry': expiry,
        'default_response': default_response
    })

    return_results(demisto.executeCommand('send-notification', {
        'to': demisto.get(demisto.args(), 'user'),
        'message': message_dict,
        'ignoreAddURL': 'true',
        'mattermost_ask': True,
        'using-brand': 'MattermostV2',
    }))


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
