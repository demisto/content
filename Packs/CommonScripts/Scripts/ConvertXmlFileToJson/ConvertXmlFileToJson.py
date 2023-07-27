import demistomock as demisto
from CommonServerPython import *
import xmltodict


def convert_file(entry_id: str, verbose: bool, context_key: str) -> None:
    """
    Converts file content from XML to Json
    Args:
        entry_id: The entry id represents the file.
        verbose: Whether to print the json result to the warroom.
        context_key: The key to insert the json data to.
    """
    xml_file = demisto.getFilePath(entry_id).get("path", "")
    with open(xml_file, 'rb') as xml:
        xml_json = xmltodict.parse(xml)
    if verbose:
        return_results(xml_json)
    if context_key:
        appendContext(key=context_key, data=xml_json)


def main():  # pragma: no cover
    args = demisto.args()
    entry_id = args.get("entryID", "")
    verbose = argToBoolean(args.get("verbose", False))
    context_key = args.get("contextKey", "")
    try:
        convert_file(entry_id, verbose, context_key)
    except Exception as e:
        return_error(f"Convert XML File to Json Failed: Error: {str(e)}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
