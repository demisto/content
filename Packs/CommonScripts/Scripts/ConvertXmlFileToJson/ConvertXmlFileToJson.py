import demistomock as demisto
from CommonServerPython import *
import xmltodict


def convert_file(entry_id: str, verbose: bool, context_key:str) -> dict:
    xml_file = demisto.getFilePath(entry_id).get("path", "")
    with open(xml_file['path'], 'rb') as xml:
        xml_json = xmltodict.parse(xml)
    if verbose:
        return_results(xml_json)
    if context_key:
        demisto.setContext(contextPath=context_key, value=xml_json)


def main():
    args = demisto.args()
    entry_id = args.get("entry_id", "")
    verbose = argToBoolean(args.get("verbose", False))
    context_key = args.get("contextKey", "")
    try:
        convert_file(entry_id, verbose, context_key)
    except Exception as e:
        return_error(f"Convert XML File to Json Failed: Error: {str(e)}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
