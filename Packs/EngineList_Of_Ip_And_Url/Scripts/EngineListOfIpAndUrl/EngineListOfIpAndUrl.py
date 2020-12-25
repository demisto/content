import json

import demistomock as demisto  # noqa: F401
import requests
from CommonServerPython import *  # noqa: F401


def get_data(url, Resource, Apikey):
    Params = {'apikey': Apikey, 'resource': Resource}
    response = requests.get(url, params=Params)
    if response.status_code == 200:
        response_dict = response.json()
        return response_dict
    else:
        print(response.text)
        print(response.raise_for_status())


def engine_list(data, name, list1, list2, list3):
    for k, v in data.items():
        if type(v) is dict:
            for i, j in data[k].items():
                if(j == "unrated site"):
                    list1.append(k)
                elif(j == "clean site"):
                    list2.append(k)
                elif(j == "malware site"):
                    list3.append(k)


def main():
    l1 = []
    l2 = []
    l3 = []
    Apikey = 'd50475512e222094e1ffed7bbf13b49b5a1e8089bf2a25290c781f2211f43cbe'
    api_url = 'https://www.virustotal.com/vtapi/v2/url/report'
    Resource = demisto.args()['IP']
    response_dict = get_data(api_url, Resource, Apikey)
    data = response_dict.get('scans')
    engine_list(data, "scans", l1, l2, l3)

    result = {"unrate_engines": l1, "clean_engines": l2, "malware_engines": l3}

    # context_key = args.get('contextKey', '')
#     results = CommandResults(
#         outputs_prefix='l1',
#         outputs=l1,
# #        readable_output=human_readable
#     )
    # return_results(results)
    # context = {}
    # if context_key:
    #     context = {context_key: results}
    # print("Total No. of engines: ", len(l1+l2+l3))
    # print("\n")
    # print("Total No. of Unrated engines: ", len(l1))
    # print("Unrated Engines : ", l1)
    # print("\n")
    # print("Total No. of Clean engines: ", len(l2))
    # print("Clean Engines : " , l2)
    # print("\n")
    # print("Total No. of Malware engines: ", len(l3))
    # print("Malware Engines : " , l3)
    demisto.results(
        {
            'Type': entryTypes["note"],
            'ContentsFormat': formats["json"],
            'Contents': result,
            'HumanReadable': result,
            'ReadableContentsFormat': formats["json"],
            'EntryContext': {"result": result}
        }
    )
# complex entry in war room
# demisto.results({
#             "Type": entryTypes["note"],
#             "ContentsFormat": formats["json"],
#             "ReadableContentsFormat": formats["markdown"],
#             "Contents" : l1,
#             "EntryContext": l1
#             "HumanReadable": md
#         })


main()
