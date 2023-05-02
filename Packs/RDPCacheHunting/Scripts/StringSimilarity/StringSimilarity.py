import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import difflib
  #import Levenshtein

def main():
    args = demisto.args()
    text = args.get('text').split()
    strings = args.get('list_of_strings').split()
    strings_list_to_match = argToList(strings)
    similiarity_threshold = float(args.get('similiarity_threshold'))
    data = []
    checked_tools = {}
    for tool in strings_list_to_match:
        for string in text:
            diff_result = difflib.SequenceMatcher(None, tool.lower(), string.lower()).ratio()
            #diff_result = difflib.get_close_matches(tool, i, n=1)
            #if bool(diff_result) == True:
            if diff_result > similiarity_threshold and len(string) > 3:
                item = {"StringFromList": tool.lower(), "StringFromText": string.lower(), "similarityRatio": round(diff_result, 2)}
                data.append(item)
    jsonData = json.dumps(data)
    jsonData = json.loads(jsonData)
    json_results = {
        "EntryContext": {"similarityCheck": jsonData},
        "Type": entryTypes['note'],
        "ContentsFormat": formats['json'],
        "Contents": jsonData
    }
    return_results(json_results)

if __name__ in ["__builtin__", "builtins", '__main__']:
    main()
