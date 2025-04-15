import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def FilterEntries(entry, maxsize: int) -> str:
    if entry['Metadata']['category'] == "procedural":
        return ""
    if entry.get('Contents', '') == "Metrics reported successfully.":
        return ""
    if entry['Metadata'].get('contentsSize', 0) > maxsize:
        return ""

    return entry


def main():
    try:
        args = demisto.args()
        ids = args.get("ids", "").split(",")
        filters = {'tags': args.get("tags", ""), 'categories': args.get("categories", "")}
        maxsize = int(args.get("maxcontentsize", "64"))
        text = ""

        for incid in ids:
            filters['id'] = incid
            results = execute_command("GetEntries", filters)
            results = results if isinstance(results, list) else [results]

            for entry in results:
                if FilterEntries(entry, maxsize) == "":
                    continue
                text += f"{entry['Metadata']['category']} {entry['Metadata'].get('dbotCreatedBy', '')}"
                text += f" {entry['Metadata']['created']}"
                text += f" {entry.get('Contents', '')} {entry.get('HumanReadable', '')}"
                text += f" {entry['Metadata'].get('tags', '')} \n"

        execute_command("setIncident", {'customFields': {'anythingllmsearchresults': text}})
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f'AnyLlmSearchXsoarEntries: error is - {ex}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
