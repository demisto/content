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
value = demisto.args().get(u'value')

results = {
    True: 'yes',
    False: 'no',
}

demisto.results(results[search(demisto.context(), path.split('.'), value)])
