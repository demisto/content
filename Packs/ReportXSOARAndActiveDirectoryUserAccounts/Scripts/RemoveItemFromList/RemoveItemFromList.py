import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# code to take in a string with several items and return as a list without one given item

# retrieve inputs
itm = (str(demisto.args().get('itemtoremove')))
lst = demisto.args().get('list')
# print('Original list',lst, type(lst))

# remove list item to delete
lst.remove(itm)
print(lst, type(lst))

# output the data to the context so it can be used for other tasks
appendContext('XSOAR.UpdatedUsers', lst)
