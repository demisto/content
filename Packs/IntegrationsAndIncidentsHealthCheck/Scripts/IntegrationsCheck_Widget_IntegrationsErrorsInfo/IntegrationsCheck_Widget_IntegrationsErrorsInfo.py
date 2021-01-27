import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    list_data = demisto.executeCommand("getList", {"listName": "XSOAR Health - Failed Integrations Table"})
    list_content = list_data[0].get('Contents', '')

    list_table = []

    if list_content:
        list_json = json.loads(list_content)
    else:
        list_json = None

    if isinstance(list_json, list):
        for instance in list_json:
            list_table.append({"Brand": instance.get('brand'), "Instance": instance.get('instance'),
                              "Category": instance.get('category'), "Information": instance.get('information')})
        demisto.results({'total': len(list_table), 'data': list_table})

    elif isinstance(list_json, dict):
        list_table.append({"Brand": list_json.get('brand'), "Instance": list_json.get('instance'),
                          "Category": list_json.get('category'), "Information": list_json.get('information')})
        demisto.results({'total': len(list_table), 'data': list_table})

    else:
        data = {"total": 1, "data": [{"Brand": "N\A", "Instance": "N\A", "Category": "N\A", "Information": "N\A"}]}
        demisto.results(data)


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
