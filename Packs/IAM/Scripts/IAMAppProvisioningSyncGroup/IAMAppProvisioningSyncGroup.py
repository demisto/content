import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# noqa: F401
# noqa: F401
from json import JSONDecodeError
import traceback


""" CONSTANTS """
GROUP_MAPPINGS_INDICATOR_FIELD = "groupmappings"
APP_PROFILES_USER_PROFILE_FIELD = "appprofiles"
ACTIVE_INDICATOR_FIELD = "active"
APP_PROVISIONING_SETTINGS_LIST_NAME = "app-provisioning-settings"

ID_FIELD = "id"
DISPLAY_NAME_FIELD = "displayName"
LAST_SYNCED_FIELD = "lastSynced"

EMAIL_NOTIFICATION_LIST = "email-notification-list"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"

USER_ADDED_TO_GROUP_MESSAGE = [
    "Successfully imported new member to an app group",
    "Add user to group membership",
]
USER_DELETED_FROM_GROUP_MESSAGE = [
    "Successfully deleted member of an app group",
    "Remove user from group membership",
]

OKTA_LOCAL_GROUP_MEMBER_ADD_EVENT_TYPE = "group.user_membership.add"
OKTA_LOCAL_GROUP_MEMBER_REMOVE_EVENT_TYPE = "group.user_membership.remove"
OKTA_LOCAL_USER_TYPE = "User"
OKTA_LOCAL_GROUP_TYPE = "UserGroup"

OKTA_IMPORTED_GROUP_MEMBER_CHANGE_EVENT_TYPE = "app.user_management"
OKTA_IMPORTED_USER_TYPE = "AppUser"
OKTA_IMPORTED_GROUP_TYPE = "AppGroup"


# This is to take care of the Okta logs that may get missed since it's not real time. It may have a delay of 1 second.
# We will go back OKTA_LOG_OVERLAP_TIME_MINUTES minutes and get logs from there.
# NOTE: Same event may get pulled twice
OKTA_FETCH_LOGS_BUFFER_MINUTES = 2

""" GLOBAL VARIABLES """
args = demisto.args()
okta_group_data = (
    json.loads(args.get("group_data"))
    if type(args.get("group_data")) is not dict
    else args.get("group_data")
)
okta_group_id = okta_group_data.get("id")
okta_group_name = okta_group_data.get("displayName")

app_instance = args.get("app_instance")
okta_instance = args.get("okta_instance")

group_mappings_updated = {}
failed_groups_list = []
failed_groups_responses = []

war_room_warning_logs = []

log_prefix = f"[{okta_group_id}][{okta_group_name}][{app_instance}]"


def main():
    try:
        start = datetime.now()

        if not (okta_group_id or okta_group_name):
            return_error(f"'id' and 'displayName' is required in 'group_data'")

        demisto.info(f"{log_prefix} Group sync started")

        # Get Group Profile Indicator
        group_profile, group_profile_id = get_demisto_group_profile(okta_group_id)

        # Get group mappings field from local group profile indicator
        group_mappings = group_profile.get(GROUP_MAPPINGS_INDICATOR_FIELD)
        # Get the group data for app
        # scim data to query using display name if group id is not mapped
        get_group_scim = {"displayName": okta_group_name}
        app_group_data = get_group(
            app_instance, scim=get_group_scim, group_mappings=group_mappings
        )

        if app_group_data.get("id"):
            update_group(app_instance, app_group_data)
        elif app_group_data.get("errorCode") == 404:
            app_group_data = create_group(
                app_instance, okta_group_name
            )  # Creates an empty group
            update_group(app_instance, app_group_data)
        else:
            raise Exception(f"{log_prefix} Unexpected app group data: {app_group_data}")

        if group_profile_id:
            # If group profile exists, update the groupmappings field with the id and last sync date
            update_demisto_group_profile(
                indicator_id=group_profile_id,
                group_mappings=group_mappings,
                group_mappings_updated=group_mappings_updated,
            )
        else:
            # Create the Group Profile indicator and update the groupmappings field with the id and last sync date
            create_demisto_group_profile(
                okta_group_id=okta_group_id, group_mappings=group_mappings_updated
            )

        if war_room_warning_logs:
            return_results(
                f"{log_prefix}: Group synced with below warnings/errors:",
                {"Warn Logs": war_room_warning_logs},
            )
        demisto.info(
            f"{log_prefix} Group sync completed. Response Time: {(datetime.now() - start).total_seconds()} seconds"
        )

    except Exception as e:
        return_error(traceback.format_exc())
        demisto.error(f"{log_prefix} Exception Caught: {traceback.format_exc()}")


def get_group(app_instance, scim, group_mappings=None):
    try:
        # Get the group id for app instance. Group id and last sync time is needed to perform delta group operations
        # If if the data is found in local group profile indicator first. If not, iam-get-group is called
        app_group_data = get_group_mappings_for_app(app_instance, group_mappings)
        if (
            app_group_data
            and app_group_data.get(ID_FIELD)
            and app_group_data.get(LAST_SYNCED_FIELD)
        ):
            demisto.debug(
                f"{log_prefix} Group Mapping found in Indicator. App group id: {app_group_data.get('id')}"
            )
        else:
            demisto.info(
                f"{log_prefix} Calling iam-get-group for {app_instance}. scim: {json.dumps(scim)}"
            )
            get_group_response = demisto.executeCommand(
                "iam-get-group",
                {"scim": scim, "includeMembers": "true", "using": app_instance},
            )

            if isError(get_group_response[0]):
                demisto.error(
                    f"{log_prefix} iam-get-group failed. Raw Response: {get_group_response}"
                )
                raise Exception(
                    f"{log_prefix} iam-get-group failed. Raw Response: {get_group_response}"
                )
            app_group_data = read_result_from_command_response(
                get_group_response, app_instance
            )
            members = app_group_data.get("members") or list()

            if not app_group_data:
                raise Exception(
                    f"{log_prefix} iam-get-group failed. Raw Response: {get_group_response}"
                )
            elif app_group_data.get("success") and app_group_data.get("id"):
                demisto.info(
                    f"{log_prefix} Completed iam-get-group for {app_instance}. group id: {app_group_data.get('id')}. "
                    f"Members: {len(members)}"
                )
            elif (
                not app_group_data.get("success")
                and app_group_data.get("errorCode") == 404
            ):
                demisto.info(f"{log_prefix} Completed iam-get-group. Group not found")
            else:
                raise Exception(
                    f"{log_prefix} iam-get-group failed. Raw Response: {get_group_response}"
                )

            demisto.debug(f"{log_prefix} Get Group data: {app_group_data}")

        return app_group_data

    except Exception as e:
        demisto.error(
            f"{okta_group_id}: Error Occurred while calling iam-get-group command for {app_instance}: {traceback.format_exc()}"
        )
        return_error(
            f"Error Occurred while calling iam-get-group command for {app_instance}: {traceback.format_exc()}"
        )


def create_group(app_instance, group_name):
    """Call iam-create-group Command to create an empty group"""

    create_group_scim = {"displayName": group_name}
    create_group_args = {"scim": create_group_scim, "using": app_instance}
    create_group_response = execute_command("iam-create-group", create_group_args)

    create_group_data = read_result_from_command_response(
        create_group_response, app_instance
    )

    if create_group_data and not create_group_data.get("success"):
        demisto.error(
            f"{log_prefix} Failed to create group. Response: {create_group_response}"
        )
        raise Exception(
            f"{log_prefix} Failed to create group. Response: {create_group_response}"
        )
    else:
        demisto.info(
            f"{log_prefix} Create group completed. Id: {create_group_data.get('id')}"
        )
        demisto.log(
            f"{log_prefix} Create group completed. Id: {create_group_data.get('id')}"
        )

    return create_group_data


def update_group(app_instance, app_group_data):
    last_synced = app_group_data.get(LAST_SYNCED_FIELD)
    current_date = datetime.now().strftime(DATE_FORMAT)

    if last_synced:
        (
            group_member_ids_to_add,
            group_member_ids_to_remove,
        ) = get_group_member_changes_since_last_sync(
            last_synced=last_synced, to_date=current_date
        )
    else:
        # Last sync time is not available. Do a full comparision and get the delta changes
        (
            group_member_ids_to_add,
            group_member_ids_to_remove,
        ) = get_group_member_changes_full_comparision(app_group_data)

    """ Check for race condition. Use case where the same member id is marked for addition as well as deletion """
    if group_member_ids_to_add and group_member_ids_to_remove:
        group_member_ids_to_add_set = set(group_member_ids_to_add)
        group_member_ids_to_remove_set = set(group_member_ids_to_remove)
        conflict_members = group_member_ids_to_add_set.intersection(
            group_member_ids_to_remove_set
        )
        if conflict_members:
            send_email(
                subject="Error: Conflict in Group Provisioning Sync",
                message=f"{log_prefix} Failed to update group. Conflict in members. "
                f"Same members marked for add and remove. Member Ids: {conflict_members}",
            )
            raise Exception(
                f"{log_prefix} Failed to update group. Conflict in members. "
                f"Same members marked for add and remove. Member Ids: {conflict_members}"
            )

    """ Call iam-update-group Command to update the group with delta changes """
    if group_member_ids_to_add or group_member_ids_to_remove:
        update_group_scim = {"id": app_group_data.get(ID_FIELD)}
        update_group_args = {"scim": update_group_scim, "using": app_instance}
        if group_member_ids_to_add:
            update_group_args["memberIdsToAdd"] = group_member_ids_to_add
        if group_member_ids_to_remove:
            update_group_args["memberIdsToDelete"] = group_member_ids_to_remove

        update_group_response = execute_command("iam-update-group", update_group_args)
        update_group_data = read_result_from_command_response(
            update_group_response, app_instance
        )

        if update_group_data and not update_group_data.get("success"):
            demisto.error(
                f"{log_prefix} Failed to update group. Response: {update_group_data}"
            )
            raise Exception(
                f"{log_prefix} Failed to update group. Response: {update_group_data}. Update_group_args: {update_group_args}"
            )
        else:
            demisto.info(
                f"{log_prefix} Update group completed for '{app_group_data.get(ID_FIELD)}'. "
                f"Users added: {len(group_member_ids_to_add)}. "
                f"Users Removed: {len(group_member_ids_to_remove)}"
            )
            update_group_mapping(app_instance, app_group_data, current_date)

        return_results(
            f"{log_prefix}: {app_group_data.get(ID_FIELD)} Members Updated",
            {
                "Members Added": group_member_ids_to_add,
                "Members Deleted": group_member_ids_to_remove,
            },
        )
    else:
        demisto.info(f"{log_prefix} No change in Group")
        demisto.log(f"{log_prefix} No change in Group")
        update_group_mapping(app_instance, app_group_data, current_date)


def get_group_member_changes_full_comparision(app_group_data):
    app_group_members = app_group_data.get("members") or list()
    demisto.info(str(app_group_members))
    demisto.info(str(type(app_group_members)))
    app_group_member_ids = []
    for member in app_group_members:
        app_group_member_ids.append(member.get("value"))

    app_group_member_ids = set(app_group_member_ids)

    # Get the group data for app
    scim = {"id": okta_group_id}
    okta_group_data = get_group(
        app_instance=okta_instance, scim=scim, group_mappings={}
    )
    okta_group_members = okta_group_data.get("members") or list()

    okta_member_ids = []
    for member in okta_group_members:
        username = member.get("display")
        # Get the id of the user in app using username obtained above.
        app_instance_user_id = get_user_id_from_app_instance(app_instance, username)
        if app_instance_user_id:
            okta_member_ids.append(app_instance_user_id)
        else:
            demisto.error(
                f"{log_prefix} {app_instance} id empty for user {username}. Skipping the user"
            )

    okta_member_ids = set(okta_member_ids)

    # okta - app: members to add in app group
    group_member_ids_to_add = list(okta_member_ids - app_group_member_ids)

    # app - okta: members to remove from app group
    group_member_ids_to_remove = list(app_group_member_ids - okta_member_ids)

    return group_member_ids_to_add, group_member_ids_to_remove


def execute_command(command_name, command_arguments, fail_on_error=True):
    command_response = demisto.executeCommand(command_name, command_arguments)

    if fail_on_error is True:
        if isError(command_response[0]):
            demisto.error(
                f"{log_prefix} Command {command_name} failed. Raw Response: {command_response}"
            )
            raise Exception(
                f"{log_prefix} Command {command_name} failed. Raw Response: {command_response}"
            )

    return command_response


def get_group_member_changes_since_last_sync(last_synced, to_date):
    group_member_ids_to_add = []
    group_member_ids_to_remove = []

    """ Get the group changes from Okta using event logs """
    okta_logs_events = get_okta_logs_for_group_changes(
        okta_group_id=okta_group_id, from_date=last_synced, to_date=to_date
    )

    """ Process the event logs and get the delta group membership changes """
    for event in okta_logs_events:
        # Each event can be either added to group or removed from group. Get the type and username.
        # DiplayName of the event is used to find if it was added or removed.
        # Okta does not have different event types for imported groups
        event_type = event.get("eventType")
        display_message = event.get("displayMessage")

        # Get the target id for the user. There can be multiple targets. We need the AppUser which will have the username
        if event_type == OKTA_IMPORTED_GROUP_MEMBER_CHANGE_EVENT_TYPE:
            target_user_type = OKTA_IMPORTED_USER_TYPE
        elif (
            event_type == OKTA_LOCAL_GROUP_MEMBER_ADD_EVENT_TYPE
            or event_type == OKTA_LOCAL_GROUP_MEMBER_REMOVE_EVENT_TYPE
        ):
            target_user_type = OKTA_LOCAL_USER_TYPE
        else:
            demisto.error(
                f"{log_prefix} Unsupported eventType for group change: {event_type}"
            )
            raise Exception(f"Unsupported eventType for group change: {event_type}")

        for target in event.get("target"):
            if target.get("type") == target_user_type:
                username = target.get("alternateId").lower()

        # Get the id of the user in app using username obtained above.
        app_instance_user_id = get_user_id_from_app_instance(app_instance, username)

        if not app_instance_user_id:
            demisto.error(
                f"{log_prefix} {app_instance} id empty for user {username}. Failed to process okta event '{display_message}'"
            )
        else:
            demisto.info(
                f"{log_prefix}: {display_message}: {username}: {app_instance_user_id}"
            )

            if display_message in USER_ADDED_TO_GROUP_MESSAGE:
                group_member_ids_to_add.append(app_instance_user_id)
            elif display_message in USER_DELETED_FROM_GROUP_MESSAGE:
                group_member_ids_to_remove.append(app_instance_user_id)
            else:
                demisto.error(
                    f"{log_prefix} Unsupported displayMessage for group change: {display_message}"
                )
                raise Exception(
                    f"Unsupported displayMessage for group change: {display_message}"
                )

    return group_member_ids_to_add, group_member_ids_to_remove


def get_okta_logs_for_group_changes(okta_group_id, from_date, to_date):
    # Convert to date format
    from_date = datetime.strptime(from_date, DATE_FORMAT)
    from_date_with_buffer = from_date - timedelta(
        minutes=int(int(OKTA_FETCH_LOGS_BUFFER_MINUTES))
    )

    # Convert to string format
    from_date_with_buffer = from_date_with_buffer.strftime(DATE_FORMAT)

    # The filter queries for okta local group changes or imported group changes. Eg: AD group imported to Okta
    # For imported groups, okta group id does not show up in logs, using group name tto query
    # For okta local groups, okta group id shows up in logs
    okta_log_filter = (
        f'(eventType eq "app.user_management" or eventType co "group.user_membership") '
        f"and "
        f'(target.id eq "{okta_group_id}" or target.displayName eq "{okta_group_name}")'
    )

    demisto.info(
        f"{log_prefix} Fetching Okta logs from '{from_date_with_buffer}' to '{to_date}'. Filter: '{okta_log_filter}'"
    )

    # Query Okta to get event logs for the group
    get_logs_response = execute_command(
        "okta-get-logs",
        {
            "filter": okta_log_filter,
            "since": from_date_with_buffer,
            "until": to_date,
            "using": okta_instance,
        },
    )

    okta_logs_events = get_logs_response[0].get("Contents", [])

    demisto.info(f"{log_prefix} Fetched Okta logs with {len(okta_logs_events)} events")

    return okta_logs_events


def get_user_id_from_app_instance(app_instance, username):
    user_id = None
    # First check if the app user id already exists in the User Profile indicator
    # Get User Profile from Demisto
    user_profile = get_demisto_user_profile(username)

    # If user profile not found locally or if it's an inactive user, the user wont be added to group or removed from group.
    if not user_profile:
        return
    elif user_profile.get(ACTIVE_INDICATOR_FIELD) == "false":
        demisto.info(
            f"{log_prefix} User '{username}' is inactive in XSOAR. Group sync skipped"
        )
        return

    # Read the appprofiles field
    app_profiles = user_profile.get(APP_PROFILES_USER_PROFILE_FIELD)
    user_data = get_app_profile(app_instance, app_profiles)

    if user_data and user_data.get("id"):
        if user_data.get("active") is False:
            demisto.info(
                f"{log_prefix} User '{username}' is inactive in the app '{app_instance}'"
            )
            user_id = None
            war_room_warning_logs.append(
                f"Warn: User '{username}' is inactive in app '{app_instance}'"
            )
        else:
            user_id = user_data.get("id")
    else:
        # Get the app username as per the mapping in app-provisioning-settings.
        # Some apps has full username as username and some have samaccountname as username
        get_user_scim = {"email": user_profile.get("email")}

        get_user_response = execute_command(
            "iam-get-user", {"user-profile": get_user_scim, "using": app_instance}
        )
        user_data = read_result_from_command_response(get_user_response, app_instance)

        if not user_data:
            raise Exception(f"Get User failed. Raw Response: {get_user_response}")
        elif user_data.get("success") and user_data.get("id"):
            user_id = user_data.get("id")
        elif not user_data.get("success") and user_data.get("errorCode") == 404:
            demisto.error(
                f"{log_prefix} User '{username}' not found in '{app_instance}'"
            )
            war_room_warning_logs.append(
                f"Warn: User '{username}' not found in '{app_instance}'"
            )
        else:
            demisto.error(
                f"{log_prefix} get-user failed for user '{username}'. Raw Response: '{get_user_response}'"
            )
            raise Exception(f"Get User failed. Raw Response: {get_user_response}")
    return user_id


def get_app_provisioning_settings():
    app_provisioning_settings_response = demisto.executeCommand(
        "getList", {"listName": APP_PROVISIONING_SETTINGS_LIST_NAME}
    )

    app_provisioning_settings = app_provisioning_settings_response[0]["Contents"]
    if type(app_provisioning_settings) != dict:
        app_provisioning_settings = json.loads(app_provisioning_settings)
    return app_provisioning_settings


def get_app_profile(app_instance, app_profiles):
    app_instance_profile = {}
    if app_profiles:
        if type(app_profiles) != dict:
            try:
                app_profiles = json.loads(app_profiles)
                app_instance_profile = app_profiles.get(app_instance, {})
            except:
                demisto.error(
                    "appprofiles field in User Profile Indicator is not valid JSON. Returning empty data"
                )
    return app_instance_profile


def get_group_mappings_for_app(app_instance, group_mappings):
    """Gets the group id, last synced time etc. for a given app instance"""
    app_group_mapping = {}
    if group_mappings:
        if type(group_mappings) != dict:
            try:
                group_mappings = json.loads(group_mappings)
                app_group_mapping = group_mappings.get(app_instance, {})
            except:
                demisto.error(
                    f"{log_prefix} 'groupmappings' field in Group Profile Indicator is not valid JSON: {group_mappings}"
                )
    return app_group_mapping


def update_group_mapping(app_instance, group_data, group_sync_time):
    group_mapping = {}
    group_mapping["displayName"] = group_data.get("displayName")
    group_mapping["id"] = group_data.get("id")

    if group_sync_time:
        group_mapping[LAST_SYNCED_FIELD] = group_sync_time
    group_mappings_updated[app_instance] = group_mapping


def get_demisto_user_profile(username):
    user_profile = {}
    user_profile_query = f'type:"User Profile" and value:"{username}"'

    user_profiles = demisto.executeCommand(
        "findIndicators", {"query": user_profile_query}
    )[0]["Contents"]

    if len(user_profiles) > 1:
        demisto.error(
            f"{log_prefix} Multiple User Profile indicators found for: {username}"
        )
        send_email(
            subject="Warn: Group Provisioning Sync - Multiple user profiles found",
            message=f"Duplicate profiles found. Please review \n\n {json.dumps(user_profiles)}",
        )

    if user_profiles and len(user_profiles) != 0:
        # Custom Fields has all the User Profile fields
        user_profile = user_profiles[0].get("CustomFields")
    else:
        demisto.error(f"{log_prefix} User Profile indicator not found for: {username}")
        war_room_warning_logs.append(
            f"Warn: User Profile indicator not found for: {username}"
        )

    return user_profile


def get_demisto_group_profile(group_id):
    group_profile = {}
    group_profile_id = None
    group_profile_query = f'type:"Group Profile" and value: {group_id}'
    group_profiles = demisto.executeCommand(
        "findIndicators", {"query": group_profile_query}
    )[0]["Contents"]
    if len(group_profiles) > 1:
        send_email(
            subject="Warn: Group provisioning Sync - Multiple group profiles found",
            message=f"Duplicate group profiles found. Please review \n\n {json.dumps(group_profiles)}",
        )
    if group_profiles and len(group_profiles) != 0:
        # Custom Fields has all the Group Profile fields
        group_profile_id = group_profiles[0].get("id")
        group_profile = group_profiles[0].get("CustomFields")
    return group_profile, group_profile_id


def update_demisto_group_profile(indicator_id, group_mappings, group_mappings_updated):
    try:
        if not group_mappings:
            group_mappings = {}
        if type(group_mappings) != dict:
            try:
                group_mappings = json.loads(group_mappings)
            except Exception as e:
                group_mappings = {}

        for app_instance, group_data in group_mappings_updated.items():
            # Retain whatever is in group mappings data. Overwrite only the ones that are updated in this call
            # Update if not empty
            group_mappings[app_instance] = group_data

        set_indicator_response = execute_command(
            "setIndicator",
            {
                "id": indicator_id,
                GROUP_MAPPINGS_INDICATOR_FIELD: json.dumps(group_mappings),
            },
            fail_on_error=False,
        )

        demisto.debug(
            "Group Mappings Data Updated in Group Profile Indicator: ", group_mappings
        )

    except Exception as e:
        return_error(
            f"{log_prefix} Error occurred while updating Group Profile Indicator {indicator_id} with the new group mappings: "
            f"Error: {traceback.format_exc()}"
        )


def create_demisto_group_profile(okta_group_id, group_mappings):
    try:
        demisto.debug(
            f"{okta_group_id}: Calling Create Indicator Command. groupmappings: {group_mappings}"
        )
        create_indicator_response = demisto.executeCommand(
            "createNewIndicator",
            {
                "value": okta_group_id,
                "displayname": okta_group_name,
                GROUP_MAPPINGS_INDICATOR_FIELD: json.dumps(group_mappings),
                "merge": True,
                "type": "Group Profile",
            },
        )

        if isError(create_indicator_response[0]):
            raise Exception(create_indicator_response[0])

        demisto.debug(f"{log_prefix} Group Profile indicator created: {group_mappings}")

    except Exception as e:
        return_error(
            f"Error occurred while creating Group Profile Indicator: {okta_group_id}"
            f"Error: {traceback.format_exc()}"
        )


def read_result_from_command_response(demisto_command_response, app_instance):
    command_generic_response = None

    for response in demisto_command_response:
        content = demisto.get(response, "Contents")
        if type(content) is list:
            content = content[0]
        if content:
            try:
                if type(content) != dict:
                    content = json.loads(content)
                if content.get("instanceName") == app_instance:
                    command_generic_response = content
                    break
            except JSONDecodeError as e:
                continue

    return command_generic_response


def get_list(list_name):
    get_list_response = demisto.executeCommand("getList", {"listName": list_name})

    if isError(get_list_response[0]):
        demisto.error(f"Could not read the list: {get_list_response[0]}")
        raise Exception(f"Error: Could not read the list: {list_name}")
        list_data = None
    else:
        list_data = demisto.get(get_list_response[0], "Contents")

    return list_data


def parse_json(json_path, json_data):
    matched_values = []
    json_path_expression = parse(json_path)
    results = json_path_expression.find(json_data)
    if len(results) >= 1:
        for result in results:
            matched_values.append(result.value)
    return matched_values


def send_email(send_to=None, subject=None, message=None, htmlbody=None):
    try:
        if not send_to:
            # Get Default Email notification list
            email_notification_list_response = demisto.executeCommand(
                "getList", {"listName": EMAIL_NOTIFICATION_LIST}
            )
            send_to = email_notification_list_response[0]["Contents"]
        if send_to:
            demisto.executeCommand(
                "send-mail",
                {
                    "to": send_to,
                    "subject": subject,
                    "body": message,
                    "htmlBody": htmlbody,
                },
            )
    except Exception as e:
        # Absorb the exception. We can just log error if send email failed.
        demisto.error("Failed to send email. Exception: " + traceback.format_exc())


def get_iam_html_body(app_instance_responses):
    htmlResults = ""

    try:
        for entry in app_instance_responses:
            htmlResults += (
                '<table bgcolor="#ffffff" '
                'style="width:100%;line-height:20px;padding:32px;border:1px '
                'solid;border-color:#f0f0f0" cellpadding="0" border="1">'
            )

            if type(entry) is not dict:
                entry = json.loads(entry)

            for key, value in entry.items():
                if value is not None:
                    htmlResults += '<tr><td style="padding-top:24px">' + key + "</td>"
                    htmlResults += (
                        '<td style="padding-top:24px">' + str(value) + "</td></tr>"
                    )

            htmlResults += "</table><br/>"
    except Exception as e:
        demisto.log(f"Error while creating HTML Email body. {traceback.format_exc()}")

    return htmlResults


"""
table_name: table name to display in war room
data: Data that will be displayed in war room and set in context
table_headers: List of column names for table
dt: Entry Context key
"""


def return_results(table_name, data, table_headers=None):
    if type(data) != list:
        data = [data]

    if table_headers:
        md = tableToMarkdown(table_name, data, table_headers)
    else:
        md = tableToMarkdown(table_name, data)

    demisto.results(
        {
            "Type": entryTypes["note"],
            "Contents": data,
            "ContentsFormat": formats["json"],
            "HumanReadable": md,
            "ReadableContentsFormat": formats["markdown"],
        }
    )


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
