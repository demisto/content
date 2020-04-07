import demistomock as demisto
from CommonServerPython import *
import re


def main():

    args = demisto.args()
    internalregex = args.get('internalRegex')
    domainName = args.get('domainName')
    hostName = argToList(args.get('hostName'))
    human_readable = []
    context_entry = []
    for element in hostName:
        if element:
            if internalregex:
                internalRegexMatch = re.match(internalregex, element)
            else:
                internalRegexMatch = None
            internalDomainMatch = re.match(".*\." + domainName + "$", element)
            context_entry.append({
                'Hostname': element,
                'IsInternal': True if internalRegexMatch or internalDomainMatch else False
            })

            if context_entry[-1]['IsInternal']:
                readable = element + ' is internal'
            else:
                readable = element + ' is external'

            human_readable.append(readable)

    return_outputs('\n'.join(human_readable), {'Endpoint': context_entry})


if __name__ in ('builtins', '__builtin__'):
    main()
