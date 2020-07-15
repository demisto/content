import json
import re

import demistomock as demisto
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]


def get_iot_config(iot_config_list_name="IOT_CONFIG"):
    iot_config = demisto.executeCommand("getList", {"listName": iot_config_list_name})
    if is_error(iot_config):
        return None
    iot_config_content = iot_config[0]['Contents']
    try:
        return json.loads(iot_config_content)
    except Exception as e:
        return_error(f'Failed to parse the IOT_CONFIG. Error: {str(e)}')


def get_raci(args):
    alert_name = args.get('alertName')
    alert_type = args.get('rawType')

    category = args.get('category', '')
    profile = args.get('profile', '')
    vendor = args.get('vendor', '')
    model = args.get('model', '')
    device_id = f'{category}|{profile}|{vendor}|{model}'

    iot_config_list_name = args.get('iotConfigListName', 'IOT_CONFIG')
    config = get_iot_config(iot_config_list_name)
    if config is None:
        return CommandResults(
            readable_output="None",
            outputs_prefix='raci',
            outputs_key_field="",
            outputs=None
        )

    result = {}

    # determine owner
    owner = None
    for d in config.get('devices', None):
        if 'device_id' in d and 'owner' in d and re.match(d['device_id'], device_id):
            owner = d['owner']
    result['owner'] = owner

    # determine raci
    raci = None
    for a in config.get('alerts', None):
        if 'iot_raw_type' in a and 'raci' in a and alert_type == a['iot_raw_type']:
            match_name = 'name_regex' not in a
            if not match_name:
                for n in a['name_regex']:
                    if re.match(n, alert_name):
                        match_name = True
                        break
            if match_name:
                raci = a['raci']

    if raci:
        r = raci['r']
        if r == "IOT_OWNER":
            result['r'] = owner
            result['r_email'] = config.get('groups', {}).get(owner, {}).get('email', None)
            result['r_snow'] = config.get('groups', {}).get(owner, {}).get('snow', None)
        else:
            result['r'] = r
            result['r_email'] = config.get('groups', {}).get(r, {}).get('email', None)
            result['r_snow'] = config.get('groups', {}).get(r, {}).get('snow', None)

        if result['r_snow'] and isinstance(result['r_snow'], dict):
            fields = result['r_snow']['fields']
            if fields:
                result['r_snow']['fields'] = ';'.join([f'{k}={v}' for k, v in fields.items()])
            cfields = result['r_snow']['custom_fields']
            if cfields:
                result['r_snow']['custom_fields'] = ';'.join([f'{k}={v}' for k, v in cfields.items()])

        i = []
        for inform in raci['i']:
            if inform == "IOT_OWNER":
                if owner is not None:
                    i.append(owner)
            else:
                i.append(inform)
        result['i'] = ', '.join(i) if i else None
        result['i_email'] = ', '.join([config.get('groups', {}).get(entry, {}).get('email', None) for entry in i]) if i else None
    else:
        result['r'] = None
        result['r_email'] = None
        result['r_snow'] = None
        result['i'] = None
        result['i_email'] = None

    return CommandResults(
        readable_output=f'{json.dumps(result)}',
        outputs_prefix='raci',
        outputs_key_field="",
        outputs=result
    )


def main():
    try:
        return_results(get_raci(demisto.args()))
    except Exception as ex:
        return_error(f'Failed to execute iot-get-raci. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
