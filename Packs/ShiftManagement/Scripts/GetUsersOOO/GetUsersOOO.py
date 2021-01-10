from CommonServerPython import *
# get current time
now = datetime.now()

# args
list_name = demisto.getArg("listname")
if not list_name:
    list_name = 'OOO List'

# update list name to start with 'OOO', so we can't overwrite other lists with this
if not list_name.startswith("OOO"):
    list_name = f"OOO {list_name}"

# clean the out of office list
demisto.executeCommand("OutOfOfficeListCleanup", {"listName": list_name})

# get the out of office list, check if the list exists, if not create it:
ooo_list = demisto.executeCommand("getList", {"listName": list_name})[0]["Contents"]


get_users_response = demisto.executeCommand('getUsers', {})
users_list = get_users_response[0]['EntryContext']['DemistoUsers']

if "Item not found" in ooo_list:
    users_list = []
else:
    # get ooo users
    ooo_users = []
    list_data = json.loads(ooo_list)
    for item in list_data:
        if item.get('offuntil'):
            off_until = datetime.strptime(item['offuntil'], '%Y-%m-%d')
            if off_until > now:
                ooo_users.append(item.get('user'))

    # keep only ooo users in users_list
    users_list = list(filter(lambda x: x['username'] in ooo_users, users_list))

if users_list:
    hr = tableToMarkdown('Out of office users', users_list)
else:
    hr = 'No analyst is out of office today.'
return_outputs(hr, {})
