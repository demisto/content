import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

MAILBOXES_CTXKEY = "Mailboxes"


def main() -> None:
    res = []
    resp = demisto.executeCommand("mimecast-query", demisto.args())

    if isError(resp[0]):
        demisto.results(resp)
    else:
        data = demisto.get(resp[0], "Contents.data")
        if data:
            users = set()
            items = demisto.get(data[0], 'items')
            if isinstance(items, list):
                for mail in items:
                    users.add(mail['displayto'])

            users = list(users)  # type: ignore
            if users:
                markdownString = '### Mailboxes with email(s) matching the query:\n'
                markdownString += "".join(['* ' + s + '\n' for s in users])
                res.append(
                    {'ContentsFormat': formats['markdown'], 'Type': entryTypes['note'], 'Contents': markdownString})

                users_str = ','.join([str(s) for s in users])
                demisto.setContext(MAILBOXES_CTXKEY, users_str)

                answer = 'yes'
            else:
                demisto.debug("\nNo relevant mails have been found\n")
                answer = 'no'
        else:
            demisto.debug("\nNo relevant mails have been found\n")
            answer = 'no'

        res.append({"Type": entryTypes["note"], "ContentsFormat": formats["text"], "Contents": answer})
        demisto.results(res)


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
