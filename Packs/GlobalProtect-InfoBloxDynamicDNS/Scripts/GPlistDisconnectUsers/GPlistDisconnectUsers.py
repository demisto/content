import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def search(context, path, value):
    '''
    searches a value in a context path.
    @param context - context tree to search in
    @param path - a path to search in the context
    @value - value to search
    '''

    if isinstance(context, dict):
        if len(path) > 0 and path[0] in context:
            return search(context[path[0]], path[1:], value)
        else:
            return False
    elif isinstance(context, list):
        # in case current context has multiple objects, search them all.
        return any([search(c, path, value) for c in context])
    else:
        # if we got to a leaf in the context
        return len(path) == 0 and context == value


path = demisto.args().get(u'path', u'')
value = demisto.args().get(u'host')
ipadd = demisto.args().get("ipadd")
domain = demisto.args().get("domain")

retval = search(demisto.context(), path.split('.'), value)

# If users from previous users is not found in current users then delete if DNS has record
if not retval:
    # !infoblox-get-refid domain=defense.local host=JUMPBOX-1 ipadd=172.16.2.201
    raw = demisto.executeCommand('infoblox-get-refid', {'host': value.lower(),
                                                        'domain': domain.lower(), 'ipadd': ipadd, 'status': 'USED', 'deletes': 'yes'})

    demisto.results(raw)
