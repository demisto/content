import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' STANDALONE FUNCTION '''


def results(data, f=None):
    res = []
    d = {}
    if isinstance(data, list):
        for x in data:
            d.update(x)
    else:
        d = data
    for k, v in d.items():
        scenario = []
        result = []
        if not isinstance(v, list):
            v = [v]
        for s in v:
            if s.get('scenario') and (not f or f in s.get('result', '')):
                scenario.append(s.get('scenario'))
                result.append(s.get('result', ''))
        if scenario:
            res.append({'realm': k, 'scenario': '\n'.join(scenario), 'result': '\n'.join(result)})
    return res


''' MAIN FUNCTION '''


def main():

    data = [
        {
            'Tufin': {
                'result': '🔶 Tufin: only runs on first Tuesday of the quarter.',
                'scenario': 'Firewall Rule Change'
            },
        },
        {
            'Whois': [
                {
                    'result': '✅ Test completed, Data is valid',
                    'scenario': 'DOMAIN'
                },
                {
                    'result': '✅ IP CIDR Test completed, Data is valid',
                    'scenario': 'IP CIDR'
                },
                {
                    'result': '✅ IP ASN Test completed, Data is valid',
                    'scenario': 'IP ASN'
                }
            ]
        }
    ]

    return_results(CommandResults(readable_output=tableToMarkdown('Results', results(data))))


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
