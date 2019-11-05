import demistomock as demisto
from CommonServerPython import *
import re


context = demisto.context()
incident = demisto.incidents()[0]


def context_lookup(key):
    if key.startswith('incident.'):
        key = key[9:]  # remove 'incident.' prefix from key
        res = demisto.get(incident, key)
        if not res:
            # check custom fields
            res = demisto.get(incident['CustomFields'], key)
        return res

    try:
        return demisto.get(context, key)
    except Exception:
        return None


def main(value, key=None):
    BODY = value
    res_body = BODY  # a copy of BODY to be modified and returned

    pattern = r'\{\{(.*)\}\}'  # for pulling out {{}} templates
    subpattern = r'(\S+)(?:\s*\|\s*(.*))?'  # for pulling out vars and transformers from the extracted template

    for m in re.finditer(pattern, BODY):
        # extract matches to run transformers on

        match = m.group(1)

        sub_m = re.search(subpattern, match)

        if sub_m:
            context_key = sub_m.group(1)
            transformer = sub_m.group(2)

        if context_key and not transformer:
            # didn't find a transformer
            context_value = context_lookup(context_key)
            transformed_value = context_value

            if not context_value:
                transformed_value = 'None'

        elif context_key and transformer:
            # found a key and a transformer
            context_value = context_lookup(context_key)

            if context_value:
                # now run the transformer
                transformed_value = demisto.executeCommand(transformer, {'value': str(context_value)})[0]['Contents']

            else:
                transformed_value = 'None'

        elif context_key:
            # no transformer was found
            transformed_value = context_lookup(context_key)

        res_body = res_body.replace(m.group(0), transformed_value, 1)  # insert result into template

    # return completed template
    if not key:
        demisto.results(res_body)
    else:
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['text'],
            'Contents': res_body,
            'EntryContext': {
                key: res_body
            }
        })


if __name__ == "__builtin__" or __name__ == "builtins":
    main(**demisto.args())
