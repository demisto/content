import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
import re

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
    alert_name = args.get('alert_name', '')
    alert_type = args.get('raw_type')

    category = args.get('category', '')
    profile = args.get('profile', '')
    vendor = args.get('vendor', '')
    model = args.get('model', '')
    device_id = f'{category}|{profile}|{vendor}|{model}'

    iot_config_list_name = args.get('iot_config_list_name', 'IOT_CONFIG')
    config = get_iot_config(iot_config_list_name)
    if config is None:
        return None

    result = {}

    # determine owner
    owner = None
    for d in config.get('devices', []):
        if 'device_id' in d and 'owner' in d and re.match(d['device_id'], device_id):
            owner = d['owner']
    result['owner'] = owner

    # determine raci
    raci = None
    for a in config.get('alerts', []):
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

            if owner is None:
                result['r_email'] = None
                result['r_snow'] = None
            else:
                e = config.get('groups', {}).get(owner, {}).get('email', None)
                if e is None:
                    default_email = config.get('groups', {}).get('DEFAULT', {}).get('email', None)
                    if default_email is not None:
                        result['r_email'] = default_email
                    else:
                        result['r_email'] = None
                else:
                    result['r_email'] = e

            result['r_snow'] = config.get('groups', {}).get(owner, {}).get('snow', None)
        elif r is not None:
            result['r'] = r

            e = config.get('groups', {}).get(r, {}).get('email', None)
            if e is None:
                default_email = config.get('groups', {}).get('DEFAULT', {}).get('email', None)
                if default_email is not None:
                    result['r_email'] = default_email
                else:
                    result['r_email'] = None
            else:
                result['r_email'] = e

            result['r_snow'] = config.get('groups', {}).get(r, {}).get('snow', None)
        else:
            result['r_email'] = None
            result['r_snow'] = None

        r_snow = result.get('r_snow', {})
        if r_snow:
            fields = r_snow.get('fields', {})
            if fields:
                r_snow['fields'] = ';'.join([f'{k}={v}' for k, v in fields.items()])
            cfields = r_snow.get('custom_fields', {})
            if cfields:
                r_snow['custom_fields'] = ';'.join([f'{k}={v}' for k, v in cfields.items()])

        i = []
        for inform in raci['i']:
            if inform == "IOT_OWNER":
                if owner is not None:
                    i.append(owner)
            else:
                i.append(inform)
        result['i'] = ', '.join(i) if i else None

        if i:
            i_email = []
            for entry in i:
                e = config.get('groups', {}).get(entry, {}).get('email', None)
                if e is None:
                    default_email = config.get('groups', {}).get('DEFAULT', {}).get('email', None)
                    if default_email is not None:
                        i_email.append(default_email)
                else:
                    i_email.append(e)
            if len(i_email) > 0:
                result['i_email'] = ', '.join(i_email)
            else:
                result['i_email'] = None
    else:
        result['r'] = None
        result['r_email'] = None
        result['r_snow'] = None
        result['i'] = None
        result['i_email'] = None

    return CommandResults(
        outputs_prefix='PaloAltoNetworksIoT.RACI',
        outputs_key_field="",
        outputs=result
    )


def main():
    try:
        return_results(get_raci(demisto.args()))
    except Exception as ex:
        return_error(f'Failed to execute iot-security-get-raci. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
