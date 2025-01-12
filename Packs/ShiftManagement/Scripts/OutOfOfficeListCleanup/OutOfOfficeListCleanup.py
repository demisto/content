from CommonServerPython import *


def main():
    # get current time
    now = datetime.now()

    # args
    list_name = demisto.getArg("listname")

    # update list name to start with 'OOO', so we can't overwrite other lists with this
    if not list_name.startswith("OOO"):
        list_name = f"OOO {list_name}"

    # get the current list
    ooo_list = demisto.executeCommand("getList", {"listName": list_name})[0]["Contents"]

    # check if the list exists, if not create it:
    if any(ele in ooo_list for ele in ["Item not found", 'null']):
        demisto.executeCommand("createList", {"listName": list_name, "listData": "[]"})
        result = demisto.executeCommand("getList", {"listName": list_name})
        if result and isinstance(result, list):
            ooo_list = result[0]["Contents"]
        else:
            ooo_list = ''

    # check status of the list, and add/remove the user from it.
    if not ooo_list or ooo_list == 'null':
        list_data = []
    else:
        list_data = json.loads(ooo_list)

    # loop the list, removing any where the offuntil is in the past
    remove = []
    new_list_data = []
    for i in list_data:
        off_until = datetime.strptime(i['offuntil'], "%Y-%m-%d")
        if off_until < now:
            remove.append(i['user'])
        else:
            new_list_data.append(i)

    if new_list_data != list_data:
        # set the list, return results
        set_list_res = demisto.executeCommand("setList", {"listName": list_name, "listData": json.dumps(new_list_data)})
        if isError(set_list_res):
            return_error(f'Failed to update the list {list_name}: {str(get_error(set_list_res))}')
        removed_users = '\n'.join(remove)
        return_results(f'The following Users were removed from the Out of Office List {list_name}:\n{removed_users}')
    else:
        return_results(f'No users removed from the list {list_name}')


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
