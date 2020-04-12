import demistomock as demisto
from CommonServerPython import *

import json

context_key =  demisto.args().get('key', '')
key_list = context_key.split('.')
inplace = demisto.args().get('inplace') == 'True'
capitalize = demisto.args().get('capitalize') == 'True'
context = demisto.context()
replace_dict = json.loads(demisto.args().get('replace_dict', "{}"))


# find the right key
for key in key_list:
    if not context:
        return_error("The context key doesn't exist.")
    context = context.get(key)

# Change Context
if isinstance(context, list) and isinstance(context[0], dict):
    cap_context = []
    for i in context:
        title_context = {}
        for k in i.keys():
            if k in replace_dict:
                title_context[replace_dict[k]] = i[k]
            elif k[0] != k[0].upper() and capitalize:
                title_context[k.title()] = i[k]
            else:
                title_context[k] = i[k]
        cap_context.append(title_context)

elif isinstance(context, dict):
    cap_context = {}
    for k in context.keys():
        if k in replace_dict:
            cap_context[replace_dict[k]] = context[k]
        elif k[0] != k[0].upper() and capitalize:
            cap_context[k.title()] = context[k]
        else:
            cap_context[k] = context[k]
else:
    return_error("Context key is not a dictionary or a list of dictionaries.")

# How to return context
if inplace:
    demisto.executeCommand("Set", {'key': context_key, 'value': cap_context})
    return_outputs(f"Capitalized {context_key} successfully")
if not inplace:
    return_outputs(f"Capitalized {context_key} successfully",{context_key: title_context}, '')
