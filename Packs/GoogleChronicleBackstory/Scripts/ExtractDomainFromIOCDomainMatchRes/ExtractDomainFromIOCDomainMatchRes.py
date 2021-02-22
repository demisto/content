from CommonServerPython import *
import traceback
import json
from typing import Dict, Any


def get_entry_context(json_res) -> Dict[str, Any]:
    return {outputPaths["domain"]: {"Name": json_res['Artifact']},
            "ChronicleIOCDomainMatches": {"Domain": json_res['Artifact'], "IOCIngestTime": json_res["IocIngestTime"],
                                          "FirstSeen": json_res["FirstAccessedTime"],
                                          "LastSeen": json_res["LastAccessedTime"]}}


def main() -> None:
    try:
        json_res = demisto.args().get('json_response', {})
        json_res = json.loads(json_res)

        ec = get_entry_context(json_res)
        demisto.results(
            {"Type": entryTypes['note'], "EntryContext": ec, "Contents": {}, "ContentsFormat": formats["json"]})
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Error occurred while extracting Domain from IOC Domain Matches response:\n{e}')


# python2 uses __builtin__ python3 uses builtins
if __name__ == '__builtin__' or __name__ == 'builtins':
    main()
