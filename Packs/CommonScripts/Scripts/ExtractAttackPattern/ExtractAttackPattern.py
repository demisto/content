import demistomock as demisto
from CommonServerPython import *

import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


def get_mitre_results(items):
    return execute_command('mitre-get-indicator-name', {'attack_ids': items})


def is_valid_attack_pattern(items) -> list:

    try:
        results = get_mitre_results(items)
        values = [content.get('value') for content in results]
        return values if values else []

    except ValueError as e:
        if 'verify you have proper integration enabled to support it' in str(e):
            demisto.info('Unsupported Command : mitre-get-indicator-name, '
                         'verify you have proper integration (MITRE ATTACK v2) enabled to support it. '
                         'This Is needed in order to auto extract MITRE IDs and translate them to Attack Pattern IOCs')
        else:
            demisto.info(f'MITRE Attack formatting script, {str(e)}')
        return []
    except Exception as e:
        demisto.info(f'MITRE Attack formatting script, {str(e)}')
        return []


def main():
    the_input = demisto.args().get('input')

    entries_list = is_valid_attack_pattern(the_input)

    if entries_list:
        return_results(entries_list)
    else:
        return_results('')


if __name__ in ("__builtin__", "builtins"):
    main()
