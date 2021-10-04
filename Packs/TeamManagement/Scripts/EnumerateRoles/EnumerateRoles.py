import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# Get arguments and obtain the roles
args = demisto.args()
roles = args.get('roles', '').split(",")

parsed_data = list()

# Get a list of all users in XSOAR
all_users = demisto.executeCommand("getUsers", {})[0]['Contents']

# For each provided role, check the user to see if they are a member and if so
# add them to the parsed_data list
for role in roles:
    parsed_data.append({
        "role": role,
        "users": [x.get('username') for x in all_users if role in x.get('allRoles', [])]
    }
    )

# Build the command results data
command_results = CommandResults(
    outputs_prefix="Roles",
    outputs_key_field="role",
    outputs=parsed_data,
    readable_output=tableToMarkdown(f"Role enumeration for {roles}:", parsed_data)
)

# Output the command results data
return_results(command_results)
