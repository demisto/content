from CommonServerPython import *

import json


def replace_context(args: dict) -> tuple:
    context = args.get('input', '')
    output_key = args.get('output_key', '')
    inplace = args.get('inplace', 'True') == 'True'
    capitalize = args.get('capitalize') == 'True'
    replace_dict = json.loads(args.get('replace_dict', "{}"))

    if not context:
        return "The context key you've entered is empty. Nothing has happened.", {}, {}

    if not isinstance(context, (list, dict)):
        return "The context key you've entered is at the lowest level and cannot be changed.", {}, {}

    def replace_func(key):
        if key in replace_dict.keys():
            return replace_dict.get(key)
        else:
            if capitalize:
                return key.title()
            return key

    new_context = createContext(context, keyTransform=replace_func)

    if inplace:
        demisto.executeCommand("Set", {'key': output_key, 'value': new_context})
        return f"Changed {output_key} successfully", {}, {}
    else:
        return f"Appended {output_key} successfully", {output_key: new_context}, {}


def main():
    hr, ec, raw = replace_context(demisto.args())
    return_outputs(hr, ec, raw)


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
