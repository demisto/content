import demistomock as demisto
from CommonServerPython import *


def get_dbot_score(resCmd: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Gets the CVE and returns its reputation according to its CVSS score.

    Args:
        resCmd (list[CommandResults]): A CVE indicator

    Returns:
        int: either 0,1,2 or 3 depending on the CVSS
    """

    results = []
    for cve in resCmd:
        if 'Contents' in cve:
            data = cve.get('Contents', {})
            cvss = data.get('cvss', -1)

            if not cvss:
                cvss = -1

            elif isinstance(cvss, dict):
                score = data.get('cvss').get('Score', -1)
                cvss = float(score) if score else -1

            if cvss == -1:
                res = 0
            elif cvss < 3:
                res = 1
            elif cvss < 7:
                res = 2
            else:
                res = 3

            results.append({
                'Type': entryTypes['note'],
                'ContentsFormat': formats['json'],
                'Contents': res,
                'EntryContext': {
                    'DBotScore': {
                        'Indicator': data.get('id'),
                        'Type': 'CVE',
                        'Score': res,
                        'Vendor': 'DBot'
                    }
                }
            })

    return results


def main():
    cves = argToList(demisto.args().get('input'))
    resCmd = demisto.executeCommand('cve', {'cve': cves})
    results = get_dbot_score(resCmd)

    if len(results) == 0:
        # resCmd is expected to be empty result
        return_results(resCmd)

    else:
        return_results(results)


if __name__ in ('__main__', 'builtin', 'builtins'):
    main()
