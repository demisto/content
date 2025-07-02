import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def parsetitle(title: str):
    # Strip the entry_id when processed text file is uploaded from XSOAR "225@12345_title" - see integration as well
    parts = title.split("_", 1)
    if len(parts) == 2 and "@" in parts[0]:
        return (parts[0], parts[1])
    else:
        return ("", title)


def main():
    try:
        args = demisto.args()
        title = args.get("title", "")
        pattern = args.get("pattern", "")
        if title == "":
            raise Exception("The document title parameter was not provided")

        documents = execute_command("anyllm-document-list", {})
        entry_id = ""

        for d in documents["localFiles"]["items"][0]["items"]:
            eid, doctitle = parsetitle(d["title"])
            if d["title"] == title.lower():
                entry_id = eid
                break

        res = []
        if entry_id != "":
            file_path = demisto.getFilePath(entry_id)["path"]
            f = open(file_path, "rb")
            data = f.read().decode("utf-8")
            f.close()
            results = re.findall(pattern, data, re.MULTILINE)
            if len(results) > 0:
                if isinstance(results[0], str):
                    execute_command("setIncident", {"customFields": {"anythingllmsearchresults": "\n".join(results)}})
                elif isinstance(results[0], tuple):
                    for r in results:
                        res.append(" ".join(r))
                    execute_command("setIncident", {"customFields": {"anythingllmsearchresults": "\n".join(res)}})
        else:
            raise Exception(f"Document [{title}] not found")

    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f"AnyLlmSearchDocument: error is - {ex}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
