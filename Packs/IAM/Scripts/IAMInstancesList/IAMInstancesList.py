import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from operator import itemgetter

iam_brands_with_non_iam_category = ["Active Directory Query v2"]


def get_state(state):
    if state == "active":
        return "Enabled"
    return "Disabled"


all_instances = demisto.getModules()
instances = []
for instance_name, details in all_instances.items():
    if (
        details.get("category") == "Identity and Access Management"
        or details.get("brand") in iam_brands_with_non_iam_category
    ) and details.get("state") == "active":
        details["name"] = instance_name
        instances.append(
            {"Instance Name": instance_name, "Brand": details.get("brand")}
        )

instances = sorted(instances, key=itemgetter("Brand"))

output = {"data": instances, "total": len(instances)}

return_outputs(json.dumps(output))
