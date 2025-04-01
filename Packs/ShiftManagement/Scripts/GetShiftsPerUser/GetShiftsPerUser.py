import demistomock as demisto
from CommonServerPython import *

from CommonServerUserPython import *

HOURS_DAYS_HEADER = "Hours / Days"
SUNDAY_HEADER = "Sunday"
MONDAY_HEADER = "Monday"
TUESDAY_HEADER = "Tuesday"
WEDNESDAY_HEADER = "Wednesday"
THURSDAY_HEADER = "Thursday"
FRIDAY_HEADER = "Friday"
SATURDAY_HEADER = "Saturday"

DAY_NUM_TO_DAY_HEADER = {
    0: SUNDAY_HEADER,
    1: MONDAY_HEADER,
    2: TUESDAY_HEADER,
    3: WEDNESDAY_HEADER,
    4: THURSDAY_HEADER,
    5: FRIDAY_HEADER,
    6: SATURDAY_HEADER,
}


def time_fix(t):
    # If the time is a single number padd it with zeros
    if t // 10 < 1:
        return "0" + str(t)
    return str(t)


def main():
    user_id = demisto.args().get("userId", False)
    if not user_id:
        get_users_res: list = demisto.executeCommand("getUsers", {"current": True})
        if is_error(get_users_res):
            return_error(f"Failed to get users: {get_error(get_users_res)!s}")
        contents = get_users_res[0]
        if contents and len(contents.get("Contents")) == 1:
            user_id = contents.get("Contents")[0].get("id")
        else:
            return_error("Failed to get users: User object is empty")

    get_roles_response: list = demisto.executeCommand("getRoles", {})
    if is_error(get_roles_response):
        return_error(f"Failed to get roles: {get_error(get_roles_response)!s}")

    get_users_response: list = demisto.executeCommand("getUsers", {})
    if is_error(get_users_response):
        return_error(f"Failed to get users: {get_error(get_users_response)!s}")

    users = get_users_response[0]["Contents"]
    user = [u for u in users if u.get("id", False) == user_id]
    if len(user) == 0:
        return_error(f"Failed to find user: {user_id!s}")

    user = user[0]
    user_roles = user.get("allRoles", [])
    if len(user_roles) == 0:
        demisto.error(f"Failed to find roles for user: {user_id!s}")
        demisto.results([])

    roles = get_roles_response[0]["Contents"]
    shifts_of_user = [r.get("shifts") for r in roles if r.get("shifts", False) and r.get("name") in user_roles]
    if len(shifts_of_user) == 0:
        demisto.error(f"Failed to find shifts for user: {user_id!s}")
        demisto.results([])

    shifts_of_user = [s for rshifts in shifts_of_user for s in rshifts]

    shifts_of_user_readable = []
    for s in shifts_of_user:
        from_day = DAY_NUM_TO_DAY_HEADER[s.get("fromDay")]
        from_hour = time_fix(s.get("fromHour"))
        from_minute = time_fix(s.get("fromMinute"))
        to_day = DAY_NUM_TO_DAY_HEADER[s.get("toDay")]
        to_hour = time_fix(s.get("toHour"))
        to_minute = time_fix(s.get("toMinute"))
        shifts_of_user_readable.append([f"{from_day} {from_hour}:{from_minute}", f"{to_day} {to_hour}:{to_minute}"])

    HEADERS = ["Start", "End"]

    shifts_table = [
        {
            HEADERS[0]: shift[0],
            HEADERS[1]: shift[1],
        }
        for shift in shifts_of_user_readable
    ]

    widget = TextWidget(text=tableToMarkdown(name=f'{user.get("name", user_id)}\'s Shifts', t=shifts_table, headers=HEADERS))
    return_results(widget)


if __name__ in ("__builtin__", "builtins", "__main__"):
    main()
