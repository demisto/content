import re

def defang(content):
    patterns = [
        (
            r"(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}",
            lambda match: match.group(0).replace(".", "[.]"),
        ),
        (
            r"https?://(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()!@:%_\+.~#?&//=]*)",
            lambda match: match.group(0)
            .replace(".", "[.]")
            .replace("https://", "hxxps[://]"),
        ),
        (
            r"[^@ \t\r\n]+@[^@ \t\r\n]+\.[^@ \t\r\n]",
            lambda match: match.group(0)
            .replace("@", "[@]")
            .replace(".", "[.]"),
        ),
    ]

    for pattern, replacer in patterns:
        content = re.sub(pattern, lambda match: replacer(match), content)

    outputs = {
        'Defang': {
            'output': content
        }
    }
    return content, outputs

if __name__ in ('__main__', 'builtins', '__builtin__'):
    try:
        input = demisto.args().get('input')
        return_outputs(*defang(input))
    except Exception as e:
        return_error('Error occurred while running the command. Exception info:\n' + str(e))

