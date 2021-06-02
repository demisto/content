import codecs
import configparser

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

CUSTOM_REG_TYPE = 'Custom'

REGISTRY_TYPE_TO_KEY = {
    'Users': [r'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'],
    'MachineStartup': [r'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run'],
    'UserStartup': [r'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run'],
    'MachineRunOnce': [r'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce'],
    'UserRunOnce': [r'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce'],
    'Services': ["HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services"],
    'DelayedServices': [r'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad'],
    'UserRecentApps': [r'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps'],
    'Timezone': [r'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\TimeZoneInformation'],
    'Networks': [r'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsNT\CurrentVersion\NetworkList\Signatures\Unmanaged',
                 r'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsNT\CurrentVersion\NetworkList\Signatures\Managed',
                 r'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsNT\CurrentVersion\NetworkList\Nla\Cache'],
    'USB': [r'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR', r'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USB'],
    'LastLoggedOnUser': [r'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI']
}

REGISTRY_SUB_FOLDER = {
    'Users': 'SID'
}


def parse_reg_value(value):
    value = value.strip('"')
    try:
        if value.startswith("hex"):
            value2 = "".join([ch for ch in value[value.find(":") + 1:].split(",") if len(ch) == 2 and ch != '00'])
            return bytearray.fromhex(value2).decode()
        if value.startswith("dword"):
            return str(int("0x" + value[value.find(":") + 1:], 16))
        return value
    except Exception:
        return value


def get_registry(entry_id):
    res = demisto.getFilePath(entry_id)
    path = res['path']
    with codecs.open(path, encoding='utf-16') as myfile:
        data = myfile.read()

    cfg = configparser.ConfigParser(strict=False, allow_no_value=True)
    cfg.optionxform = str  # type: ignore[assignment, assignment]
    cfg.read_string(data[data.find("["):], )
    reg = {}  # type: ignore[var-annotated]
    for section in cfg.sections():
        try:
            if section not in reg:
                reg[section] = {}
            items = cfg.items(section)
            reg[section].update(dict(items))
        except Exception:
            reg[section] = {}
            continue

    return reg


def get_sub_keys(reg, key, folder_output_key):
    all_folders = {k for k in reg if k.startswith(key)}
    users = []
    records = []
    for folder in all_folders:
        new_key = folder[len(key):].strip("\\")
        if new_key:
            user = reg[folder]
            user = {k.strip('"'): parse_reg_value(v) for k, v in user.items()}
            user[folder_output_key] = new_key
            for registry_key, registry_value in user.items():
                record = {
                    'Type': 'Services',
                    'RegistryPath': folder,
                    'RegistryKey': registry_key,
                    'RegistryValue': registry_value
                }
                records.append(record)
            users.append(user)
    return records, users


def get_reg_users(reg):
    key = REGISTRY_TYPE_TO_KEY['Users'][0]
    records, users = get_sub_keys(reg, key, 'Sid')
    return records, {'Users': users}


def get_reg_services(reg):
    key = REGISTRY_TYPE_TO_KEY['Services'][0]
    records, users = get_sub_keys(reg, key, 'Service')
    return records, {'Services': users}


def get_reg_results(reg, type_to_keys):
    records = []  # type: ignore[var-annotated]
    type_records = {}  # type: ignore[var-annotated]
    for _type, keys in type_to_keys.items():
        if _type == 'Users':
            users_records, users_type_records = get_reg_users(reg)
            records += users_records
            type_records.update(users_type_records)
        elif _type == 'Services':

            services_records, services_type_records = get_reg_services(reg)
            records += services_records
            type_records.update(services_type_records)
        elif _type == 'LastLoggedOnUser':
            key = REGISTRY_TYPE_TO_KEY['LastLoggedOnUser'][0]
            values = reg.get(key, {})
            registry_value = values.get('"LastLoggedOnUser"')
            if registry_value:
                registry_value = parse_reg_value(registry_value)
                records.append({
                    'Type': 'LastLoggedOnUser',
                    'RegistryPath': key,
                    'RegistryKey': 'LastLoggedOnUser',
                    'RegistryValue': registry_value
                })
                type_records['LastLoggedOnUser'] = registry_value
        else:
            all_keys = []  # type: ignore[var-annotated]
            for key in keys:
                all_keys += [k for k in reg if k.startswith(key)]
            for key in all_keys:
                registry_keys_values = reg.get(key)
                dict_key = _type if _type != CUSTOM_REG_TYPE else key
                if dict_key not in type_records:
                    type_records[dict_key] = []
                if registry_keys_values:
                    registry_keys_values = {k.strip('"'): parse_reg_value(v) for k, v in registry_keys_values.items()}
                    type_records[dict_key].append(registry_keys_values)
                    for registry_key, registry_value in registry_keys_values.items():
                        record = {
                            'Type': _type,
                            'RegistryPath': key,
                            'RegistryKey': registry_key,
                            'RegistryValue': registry_value
                        }
                        records.append(record)
    return records, type_records


def main():
    reg = get_registry(demisto.args()['entryID'])
    registry_data = demisto.args()['registryData']
    if registry_data == 'All':
        registry_types = REGISTRY_TYPE_TO_KEY.keys()
    elif registry_data == 'None':
        registry_types = []  # type: ignore[assignment]
    else:
        registry_types = argToList(registry_data)
        registry_types = [x for x in registry_types if x in REGISTRY_TYPE_TO_KEY]  # type: ignore[assignment]

    registry_types_to_keys = {k: REGISTRY_TYPE_TO_KEY[k] for k in registry_types}
    custom_reg_paths = demisto.args().get('customRegistryPaths')
    if custom_reg_paths:
        for reg_path in argToList(custom_reg_paths):
            reg_path = reg_path.strip()
            if reg_path:
                if CUSTOM_REG_TYPE not in registry_types_to_keys:
                    registry_types_to_keys[CUSTOM_REG_TYPE] = []
                registry_types_to_keys[CUSTOM_REG_TYPE].append(reg_path)

    records, type_records = get_reg_results(reg, registry_types_to_keys)

    hr = tableToMarkdown("Registry Results", records[:50])
    return_outputs(hr, {"RegistryForensicDataRaw": records, 'RegistryForensicData': type_records}, records)


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
