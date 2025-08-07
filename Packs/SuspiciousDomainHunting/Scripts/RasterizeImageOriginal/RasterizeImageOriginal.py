import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def get_entry_id(demisto_context):
    entry_id = ""
    files = []

    try:
        files = demisto_context["InfoFile"]
        if isinstance(files, list):
            for file in files:
                if str(file["Name"]).startswith("original"):
                    entry_id = file["EntryID"]
                    break
        else:
            entry_id = files["EntryID"]

        return entry_id
    except Exception as e:
        demisto.debug(f"Error: {e}")


def main():
    demisto_context = demisto.context()

    entry_id = get_entry_id(demisto_context)

    server_url_res = demisto.executeCommand("GetServerURL", {})
    if server_url_res and len(server_url_res) > 0:
        server_url = server_url_res[0].get("Contents")
    else:
        server_url = ""
        demisto.debug(f"{server_url_res=} -> {server_url=}")

    link = f"{server_url}/entry/download/{entry_id}" if server_url else None

    if entry_id and link:
        html = f"<-:->![pic]({link})\n[Download]({link})"

    else:
        html = "<-:->No Image, try to refresh"

    demisto.results(
        {
            "ContentsFormat": formats["markdown"],
            "Type": entryTypes["note"],
            "Contents": html,
        }
    )


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
