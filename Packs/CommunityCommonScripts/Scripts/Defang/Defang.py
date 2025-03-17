import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import re


def defang(content, defang_options, mail_options, url_options):
    if "ip" in defang_options:
        ip_regex = r"(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}"
        content = re.sub(
            ip_regex, lambda match: match.group(0).replace(".", "[.]"), content
        )

    if "mail" in defang_options:
        mail_regex = r"[^@ \t\r\n]+@[^@ \t\r\n]+\.[^@ \t\r\n]+"
        if "dot" in mail_options and "at" in mail_options:
            content = re.sub(
                mail_regex,
                lambda match: match.group(0).replace(".", "[.]").replace("@", "[@]"),
                content,
            )
        elif "dot" in mail_options:
            content = re.sub(
                mail_regex, lambda match: match.group(0).replace(".", "[.]"), content
            )
        elif "at" in mail_options:
            content = re.sub(
                mail_regex, lambda match: match.group(0).replace("@", "[@]"), content
            )

    if "url" in defang_options:
        url_regex = r"https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()!@:%_\+.~#?&\/\/=]*)"
        if "dot" in url_options and "http" in url_options and "colon" in url_options:
            content = re.sub(
                url_regex,
                lambda match: match.group(0)
                .replace(".", "[.]")
                .replace("https", "hxxps")
                .replace("://", "[://]"),
                content,
            )
        elif "dot" in url_options and "http" in url_options:
            content = re.sub(
                url_regex,
                lambda match: match.group(0)
                .replace(".", "[.]")
                .replace("https", "hxxps"),
                content,
            )
        elif "dot" in url_options and "colon" in url_options:
            content = re.sub(
                url_regex,
                lambda match: match.group(0)
                .replace(".", "[.]")
                .replace("://", "[://]"),
                content,
            )
        elif "http" in url_options and "colon" in url_options:
            content = re.sub(
                url_regex,
                lambda match: match.group(0)
                .replace("https", "hxxps")
                .replace("://", "[://]"),
                content,
            )
        elif "dot" in url_options:
            content = re.sub(
                url_regex, lambda match: match.group(0).replace(".", "[.]"), content
            )
        elif "http" in url_options:
            content = re.sub(
                url_regex,
                lambda match: match.group(0).replace("https", "hxxps"),
                content,
            )
        elif "colon" in url_options:
            content = re.sub(
                url_regex, lambda match: match.group(0).replace("://", "[://]"), content
            )

    outputs = {"Defang": {"output": content}}

    return content, outputs


if __name__ in ("__main__", "builtins", "__builtin__"):
    try:
        input = demisto.args().get("input")
        defang_options = demisto.args().get("defang_options")
        mail_options = demisto.args().get("mail_options")
        url_options = demisto.args().get("url_options")
        return_outputs(*defang(input, defang_options, mail_options, url_options))
    except Exception as e:
        return_error(f"Error occurred while running the command. Exception info:\n{str(e)}")
