import demistomock as demisto
from CommonServerPython import *

import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


def is_valid_attack_pattern(items):

    try:
        results = demisto.executeCommand('mitre-get-indicator-name', {'attack_ids': items})
        list_contents = results[0]['Contents']
        values = [content.get('value') for content in list_contents]
        return values if values else False

    except ValueError as e:
        if 'verify you have proper integration enabled to support it' in str(e):
            demisto.info('Unsupported Command : mitre-get-attack-pattern-value, '
                         'verify you have proper integration (MITRE ATTACK v2) enabled to support it. '
                         'This Is needed in order to auto extract MITRE IDs and translate them to Attack Pattern IOCs')
        else:
            demisto.info(f'MITRE Attack formatting script, {str(e)}')
        return False
    except Exception as e:
        demisto.info(f'MITRE Attack formatting script, {str(e)}')
        return False


def main():
    attack_list = argToList(demisto.args().get('input'))
    list_results = is_valid_attack_pattern(attack_list)

    if list_results:
        demisto.results(list_results)
    else:
        demisto.results('')


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins" or __name__ == "__main__":
    main()
