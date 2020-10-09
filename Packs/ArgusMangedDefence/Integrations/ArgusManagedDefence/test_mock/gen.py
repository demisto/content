from CommonServerPython import camel_case_to_underscore
string = """param int startTimestamp: 
    :param int endTimestamp: 
    :param int limit: Set this value to set max number of results. By default, no restriction on result set size. 
    :param int offset: Set this value to skip the first (offset) objects. By default, return result from first object. 
    :param bool includeDeleted: Set to true to include deleted objects. By default, exclude deleted objects. 
    :param list subCriteria: Set additional criterias which are applied using a logical OR. 
    :param bool exclude: Only relevant for subcriteria. If set to true, objects matching this subcriteria object will be excluded. 
    :param bool required: Only relevant for subcriteria. If set to true, objects matching this subcriteria are required (AND-ed together with parent criteria). 
    :param list customerID: Restrict search to data belonging to specified customers. 
    :param list caseID: Restrict search to specific cases (by ID). 
    :param list customer: Restrict search to specific customers (by ID or shortname). 
    :param list type: Restrict search to entries of one of these types. 
    :param list service: Restrict search to entries of one of these services (by service shortname or ID). 
    :param list category: Restrict search to entries of one of these categories (by category shortname or ID). 
    :param list status: Restrict search to entries of one of these statuses. 
    :param list priority: Restrict search to entries with given priorties 
    :param list assetID: Restrict search to cases associated with specified assets (hosts, services or processes) 
    :param list tag: Restrict search to entries matching the given tag criteria. 
    :param list workflow: Restrict search to entries matching the given workflow criteria. 
    :param list field: Restrict search to entries matching the given field criteria. 
    :param list keywords: Search for keywords. 
    :param list timeFieldStrategy: Defines which timestamps will be included in the search (default all). 
    :param str timeMatchStrategy: Defines how strict to match against different timestamps (all/any) using start and end timestamp (default any) 
    :param list keywordFieldStrategy: Defines which fields will be searched by keywords (default all supported fields). 
    :param str keywordMatchStrategy: Defines the MatchStrategy for keywords (default match all keywords). 
    :param list user: Restrict search to cases associated with these users or user groups (by ID or shortname). 
    :param list userFieldStrategy: Defines which user fields will be searched (default match all user fields). 
    :param bool userAssigned: If set, limit search to cases where assignedUser field is set/unset 
    :param bool techAssigned: If set, limit search to cases where assignedTech field is set/unset 
    :param bool includeWorkflows: If true, include list of workflows in result. Default is false (not present). 
    :param bool includeDescription: If false, omit description from response. Default is true (description is present). 
    :param list accessMode: If set, only match cases which is set to one of these access modes 
    :param list explicitAccess: If set, only match cases which have explicit access grants matching the specified criteria 
    :param list sortBy: List of properties to sort by (prefix with "-" to sort descending). 
    :param list includeFlags: Only include objects which have includeFlags set. 
    :param list excludeFlags: Exclude objects which have excludeFlags set. """

code = f'result = advanced_case_search(\n'
for line in string.split("\n"):
    cmd = line.strip().split(" ")
    cmd = cmd[2].replace(":", "")
    demisto_cmd = camel_case_to_underscore(cmd)
    code += f'\t{cmd}={demisto_cmd},\n'
code += ")"
print(code)