"""
Gets an instance configuration and a parameter to modify, to check if is works.
"""
from typing import Iterable

from CommonServerPython import *


def get_errors(response: Union[list, dict]) -> List[str]:
    errors = ''
    if is_error(response):
        errors = get_error(response)
    return errors.splitlines()


def change_keys(instance: dict, keys: Iterable) -> dict:
    for key in keys:
        new_value = not instance['configvalues'][key]
        instance['configvalues'][key] = new_value
        for i, item in enumerate(instance['data']):
            if item['name'] == key:
                instance['data'][i]['value'] = new_value
                break
        else:
            return_error(f'Could not find the {key} parameter')
    return instance


def save_configuration(arguments: dict) -> List[str]:
    res = demisto.executeCommand(
        'demisto-api-put',
        {
            'uri': 'settings/integration',
            'body': arguments
        })
    return get_errors(res)


def execute_test_module(arguments: dict) -> List[str]:
    res = demisto.executeCommand(
        'demisto-api-post',
        {
            'uri': '/settings/integration/test',
            'body': arguments
        }
    )
    errors = get_errors(res)
    if errors:
        return errors
    contents = res[0]['Contents']['response']
    if contents['success'] is False:
        errors.append(contents.get('message', 'Command failed but no message provided'))
    return errors


def main():
    args = demisto.args()
    instance = args.get('parameters')
    if not instance:
        instance = {}
    elif isinstance(instance, str) and instance:
        instance = json.dumps(instance)
    instance_name = instance['name']
    keys_in_instance = argToList(args.get('keys'))
    instance = change_keys(instance, keys_in_instance)
    try:
        errors = execute_test_module(instance)
        context = {
            'TroubleshootTestInstance(obj.instance_name === val.instance_name and val.changed_keys === obj.changed_keys)': {
                'instance_name': instance_name,
                'Errors': errors,
                'changed_keys': keys_in_instance,
                'succeed': not bool(errors)
            }
        }
        if errors:
            err_str = "\n".join(errors)
            human_readable = f'Found errors in instance {instance_name} after changing the next keys: ' \
                             f'{", ".join(keys_in_instance)}\n' \
                             f'Errors:\n{err_str}'
            return_error(human_readable, outputs=context)
        else:
            human_readable = f'Found no errors for instance {instance_name}'
            return_outputs(human_readable, context)
    finally:
        # Revert changed instance if changed
        if keys_in_instance:
            instance = change_keys(instance, keys_in_instance)
            if save_configuration(instance):
                return_error(
                    f'Could not revert instance to original configuration. Changed keys: {", ".join(keys_in_instance)}'
                )


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
