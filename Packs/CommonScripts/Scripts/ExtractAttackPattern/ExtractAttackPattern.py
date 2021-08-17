import demistomock as demisto
from CommonServerPython import *

import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


def is_valid_attack_pattern(items):

    try:
        results = demisto.executeCommand('mitre-get-indicator-name', {'attack_ids': items})
        list_contents = results[2]['Contents']
        values = [content.get('value') for content in list_contents]
        return values if values else False

    except ValueError as e:
        if 'verify you have proper integration enabled to support it' in str(e):
            demisto.info('Unsupported Command : mitre-get-indicator-name, '
                         'verify you have proper integration (MITRE ATTACK v2) enabled to support it. '
                         'This Is needed in order to auto extract MITRE IDs and translate them to Attack Pattern IOCs')
        else:
            demisto.info(f'MITRE Attack formatting script, {str(e)}')
        return False
    except Exception as e:
        demisto.info(f'MITRE Attack formatting script, {str(e)}')
        return False


def main():
    the_input = demisto.args().get('input')

    entries_list = is_valid_attack_pattern(the_input)

    if entries_list:
        return_results(entries_list)
    else:
        return_results('')


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
