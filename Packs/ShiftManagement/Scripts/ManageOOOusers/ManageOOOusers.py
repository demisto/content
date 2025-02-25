from CommonServerPython import *  # noqa: F401


def _get_current_user():
    current_username = demisto.executeCommand("getUsers", {"current": True})
    if isError(current_username):
        demisto.debug(f"failed to get current username - {get_error(current_username)}")
        return
    else:
        return current_username[0]["Contents"][0]['username']


def main():
    # get current time
    now = datetime.now()

    # args
    list_name = demisto.getArg("listname")
    username = demisto.getArg("username")

    option = demisto.getArg("option")
    days_off = now + timedelta(days=int(demisto.getArg("daysoff")))
    off_until = days_off.strftime("%Y-%m-%d")

    # update list name to start with 'OOO', so we can't overwrite other lists with this
    if not list_name.startswith("OOO"):
        list_name = f"OOO {list_name}"

    current_user = _get_current_user()
    if not current_user and not username:
        return_error('Failed to get current user. Please set the username argument in the script.')

    if not username:
        # Current user was found, running script on it.
        username = current_user
    else:
        # check if provided username is a valid xsoar user
        users = demisto.executeCommand("getUsers", {})
        if isError(users):
            return_error(f'Failed to get users: {str(get_error(users))}')
        users = users[0]['Contents']

        users = [x['username'] for x in users]
        if username not in users:
            return_error(message=f"{username} is not a valid user")

    # get the out of office list, check if the list exists, if not create it:
    ooo_list = demisto.executeCommand("getList", {"listName": list_name})[0]["Contents"]
    if isError(ooo_list):
        return_error(f'Failed to get users out of office: {str(get_error(ooo_list))}')

    if "Item not found" in ooo_list:
        demisto.results(demisto.executeCommand("createList", {"listName": list_name, "listData": "[]"}))
        ooo_list = demisto.executeCommand("getList", {"listName": list_name})[0]["Contents"]

    # check status of the list, and add/remove the user from it.
    if not ooo_list:
        list_data = []
    else:
        list_data = json.loads(ooo_list)
    if option == "add":
        # check if user is already in the list, and remove, to allow updating
        list_data = [i for i in list_data if not (i['user'] == username)]
        list_data.append({"user": username,
                          "offuntil": off_until,
                          "addedby": current_user if current_user else 'DBot'})
    else:
        # remove the user from the list.
        list_data = [i for i in list_data if not (i['user'] == username)]

    set_list_res = demisto.executeCommand("setList", {"listName": list_name, "listData": json.dumps(list_data)})
    if isError(set_list_res):
        return_error(f'Failed to update the list {list_name}: {str(get_error(set_list_res))}')

    # welcome back, or see ya later!
    if option == "add":
        demisto.results(f"Vacation mode engaged until {off_until}, enjoy the time off {username}")
    else:
        demisto.results(f"Welcome back {username}, it's like you never left!")


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
