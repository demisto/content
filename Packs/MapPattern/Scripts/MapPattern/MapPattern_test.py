import demistomock as demisto
import json


def test_main(mocker):
    from MapPattern import main

    test_data = [
        {
            'algorithm': 'regmatch',
            'caseless': 'true',
            'priority': 'first_match',
            'context': None,
            'flags': '',
            'comparison_fields': '',
            'mappings':
                '''
                {
                    "Unknown": 0,
                    "Informational|Info": 0.5,
                    "Low": 1,
                    "Medium": 2,
                    "High": 3,
                    "Critical": 4
                }
                ''',
            'patterns': [
                {
                    'value': 'High',
                    'result': 3
                },
                {
                    'value': 'Abc',
                    'result': 'Abc'
                }
            ]
        },
        {
            'algorithm': 'wildcard',
            'caseless': 'true',
            'priority': 'first_match',
            'context': None,
            'flags': '',
            'comparison_fields': '',
            'mappings':
                '''
                {
                    "*Low*": "low",
                    "*Medium*": "medium",
                    "*High*": "high",
                    "*": "unknown"
                }
                ''',
            'patterns': [
                {
                    'value': '1 - Low',
                    'result': 'low'
                },
                {
                    'value': 'high (3)',
                    'result': 'high'
                }
            ]
        },
        {
            'algorithm': 'regex',
            'caseless': 'true',
            'priority': 'first_match',
            'context': None,
            'flags': '',
            'comparison_fields': '',
            'mappings':
                '''
                {
                    "( *(Re: *|Fw: *)*)(.*)": "\\\\3"
                }
                ''',
            'patterns': [
                {
                    'value': 'Re: Re: Fw: Hello!',
                    'result': 'Hello!'
                },
                {
                    'value': 'Hello!',
                    'result': 'Hello!'
                }
            ]
        },
        {
            'algorithm': 'regex',
            'caseless': 'true',
            'priority': 'first_match',
            'context': None,
            'flags': '',
            'comparison_fields': '',
            'mappings':
                '''
                {
                    "([^@]+)@.+": "\\\\1",
                    "[^\\\\\\\\]+\\\\\\\\(.+)": "\\\\1",
                    "[a-zA-Z_]([0-9a-zA-Z\\\\.-_]*)": null,
                    ".*": "<unknown>"
                }
                ''',
            'patterns': [
                {
                    'value': 'username@domain',
                    'result': 'username'
                },
                {
                    'value': 'domain\\username',
                    'result': 'username'
                },
                {
                    'value': 'username',
                    'result': 'username'
                },
                {
                    'value': '012abc$',
                    'result': '<unknown>'
                }
            ]
        },
        {
            'algorithm': 'regex',
            'caseless': 'true',
            'priority': 'first_match',
            'context': None,
            'flags': '',
            'comparison_fields': '',
            'mappings':
                '''
                {
                    "\\"(.*)\\"": {
                        "output": "\\\\1",
                        "next": {
                            "([^@]+)@.+": "\\\\1",
                            "[^\\\\\\\\]+\\\\\\\\(.+)": "\\\\1",
                            "[a-zA-Z_]([0-9a-zA-Z\\\\.-_]*)": null,
                            ".*": "<unknown>"
                        }
                    },
                    "([^@]+)@.+": "\\\\1",
                    "[^\\\\\\\\]+\\\\\\\\(.+)": "\\\\1",
                    "[a-zA-Z_]([0-9a-zA-Z\\\\.-_]*)": null,
                    ".*": "<unknown>"
                }
                ''',
            'patterns': [
                {
                    'value': '"username@domain"',
                    'result': 'username'
                },
                {
                    'value': 'username@domain',
                    'result': 'username'
                },
                {
                    'value': '"domain\\username"',
                    'result': 'username'
                },
                {
                    'value': 'domain\\username',
                    'result': 'username'
                },
                {
                    'value': '"username"',
                    'result': 'username'
                },
                {
                    'value': 'username',
                    'result': 'username'
                },
                {
                    'value': '012abc$',
                    'result': '<unknown>'
                }
            ]
        },
        {
            'algorithm': 'regex',
            'caseless': 'true',
            'priority': 'first_match',
            'context': None,
            'flags': '',
            'comparison_fields': '',
            'mappings':
                '''
                [
                    {
                        "([^.]+)\\\\.([^@]+)@.+": {
                          "exclude": ".*@example2.com",
                          "output": "\\\\1 \\\\2"
                        }
                    },
                    {
                        "([^.]+)\\\\.([^@]+)@.+": "\\\\2 \\\\1",
                        "([^@]+)@.+": "\\\\1"
                    }
                ]
                ''',
            'patterns': [
                {
                    'value': 'john.doe@example1.com',
                    'result': 'john doe'
                },
                {
                    'value': 'doe.john@example2.com',
                    'result': 'john doe'
                },
                {
                    'value': 'username@example1.com',
                    'result': 'username'
                }
            ]
        },
        './test_data/test-1.json',
        {
            'algorithm': 'wildcard',
            'caseless': 'true',
            'priority': 'first_match',
            'context': None,
            'flags': '',
            'comparison_fields': 'IP, Host',
            'mappings':
                '''
                {
                    "IP": {
                        "127.*": "localhost"
                    },
                    "Host": {
                        "*.local": "localhost",
                        "*": "other"
                    }
                }
                ''',
            'patterns': [
                {
                    'value': {"IP": "127.0.0.1"},
                    'result': 'localhost'
                },
                {
                    'value': {"Host": "localhost"},
                    'result': 'localhost'
                },
                {
                    'value': {"IP": "192.168.1.1"},
                    'result': 'other'
                }
            ]
        }
    ]

    for t in test_data:
        if isinstance(t, str):
            with open(t, 'r') as f:
                t = json.load(f)

        for pattern in t['patterns']:
            mocker.patch.object(demisto, 'args', return_value={
                'value': pattern['value'],
                'algorithm': t['algorithm'],
                'caseless': t['caseless'],
                'priority': t['priority'],
                'context': t['context'],
                'flags': t['flags'],
                'comparison_fields': t['comparison_fields'],
                'mappings': t['mappings']
            })
        mocker.patch.object(demisto, 'results')
        main()
        assert demisto.results.call_count == 1
        results = demisto.results.call_args[0][0]
        assert json.dumps(results) == json.dumps(pattern['result'])
