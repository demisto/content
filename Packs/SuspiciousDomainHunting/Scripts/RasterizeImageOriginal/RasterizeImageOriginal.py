import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from time import sleep


def get_entry_id():
    entry_id = ''
    files = []

    for index in range(1, 4):
        try:
            files = demisto.context()['InfoFile']

        except KeyError:
            sleep(index * 2)

    try:
        for file in files:
            if str(file['Name']).startswith('original'):
                entry_id = file['EntryID']
                break

    except TypeError as e:
        entry_id = file['Name']
        demisto.results(f"Error: {e}")

    return entry_id


def main():

    demisto.context()

    entry_id = get_entry_id()

    server_url_res = demisto.executeCommand("GetServerURL", {})
    if server_url_res and len(server_url_res) > 0:
        server_url = server_url_res[0].get("Contents")

    link = f"{server_url}/entry/download/{entry_id}" if server_url else None

    if entry_id and link:
        html = f"<-:->![pic]({link})\n[Download]({link})"

    else:
        html = "<-:->No Image"

    demisto.results(
        {
            "ContentsFormat": formats["markdown"],
            "Type": entryTypes["note"],
            "Contents": html,
        }
    )


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
