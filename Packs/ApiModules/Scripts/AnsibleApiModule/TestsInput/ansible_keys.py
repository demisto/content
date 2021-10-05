MOCK_ANSIBLE_DICT = {
    'ansible_result': '0',
    'test': 'string',
    'lvl2': {'ansible_facts': 'long list of data'}
}

EXPECTED_ANSIBLE_DICT = {
    'result': '0',
    'test': 'string',
    'lvl2': {'facts': 'long list of data'}
}

MOCK_ANSIBLELESS_DICT = {
    'result': '0',
    'test': 'string',
    'lvl2': {'facts': 'long list of data'}
}

EXPECTED_ANSIBLELESS_DICT = {
    'result': '0',
    'test': 'string',
    'lvl2': {'facts': 'long list of data'}
}