import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

DictionaryOfLists = []
test_keys = ['reputation', 'ip', 'clean_engines', 'malware_engines', 'unrate_engines']


Arraylist1 = demisto.args().get("Arraylist1")
Arraylist1 = argToList(Arraylist1)

Arraylist2 = demisto.args().get("Arraylist2")
Arraylist2 = argToList(Arraylist2)

Arraylist3 = demisto.args().get("Arraylist3")
Arraylist3 = argToList(Arraylist3)

Arraylist4 = demisto.args().get("Arraylist4")
Arraylist4 = argToList(Arraylist4)

Arraylist5 = demisto.args().get("Arraylist5")
Arraylist5 = argToList(Arraylist5)


for (reputation, ip, clean_engines, malware_engines, unrate_engines) in zip(Arraylist1, Arraylist2, Arraylist3, Arraylist4, Arraylist5):
    DictionaryOfLists.append({"reputation": reputation, "ip": ip, "clean_engines": clean_engines,
                              "malware_engines": malware_engines, "unrate_engines": unrate_engines})


demisto.results(str(DictionaryOfLists))

#res= tableToMarkdown("iptable",DictionaryOfLists)

# complex entry in war room
demisto.results({
    "Type": entryTypes["note"],
    "ContentsFormat": formats["json"],
    "ReadableContentsFormat": formats["markdown"],
    "Contents": DictionaryOfLists,
    "EntryContext": {"csvResult": DictionaryOfLists}
})


# for i in range(len(test_keys)):
#     data={test_keys[0]:Arraylist1[i],
#     test_keys[1]:Arraylist2[i]}
#     DictionaryOfLists.append(data)
# demisto.results(DictionaryOfLists)
