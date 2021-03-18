import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

args = demisto.args()
cliName = args.get("cliName")
name = args.get("name")
new = args.get("new")
old = args.get("old")
selectValues = args.get("selectValues")
user = args.get("user", {})
user_id = user.get("id", None) if user else None
if user_id not in ["", "DBot", None]:
    return_error(f"{user_id} is not allowed to modify this field manually")
