import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from operator import itemgetter

iam_brands_with_non_iam_category = ["Active Directory Query v2"]

integrations = set([])

all_instances = demisto.getModules()

for instance_name, details in all_instances.items():
    if (
        details.get("category") == "Identity and Access Management"
        or details.get("brand") in iam_brands_with_non_iam_category
    ) and details.get("state") == "active":
        integrations.add(details.get("brand"))

return_outputs(len(integrations))
