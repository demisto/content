import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
list1_name = demisto.args().get("list1_name")
list2_name = demisto.args().get("list2_name")

list1_res = demisto.executeCommand("getList", {"listName": list1_name})
list2_res = demisto.executeCommand("getList", {"listName": list2_name})

if list1_res[0]["Type"] == 1 and list2_res[0]["Type"] == 1:
    list1 = list1_res[0]["Contents"].split(",")
    list2 = list2_res[0]["Contents"].split(",")

    for ip in list1:
        if ip not in list2:
            demisto.results(ip)
else:
    demisto.results("Error getting lists")


# ip1 = 10.1.1.1,10.2.2.2
# ip2 = 10.1.1.1,10.1.1.2,10.1.1.3

# !compare_list list1_name=ip1 list2_name=ip2
# DBot Result
#  10.2.2.2
