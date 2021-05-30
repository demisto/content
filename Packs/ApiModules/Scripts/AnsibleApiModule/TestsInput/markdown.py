MOCK_SINGLE_LEVEL_LIST = [
    1,
    'b',
    3,
    'x'
]

EXPECTED_MD_LIST = """  * 0: 1
  * 1: b
  * 2: 3
  * 3: x
"""

MOCK_SINGLE_LEVEL_DICT = {
    'Server': 'abc',
    'IP': '123.123.123.123',
    'Changed': 'Yes'
}

EXPECTED_MD_DICT = """  * Server: abc
  * IP: 123.123.123.123
  * Changed: Yes
"""

MOCK_MULTI_LEVEL_DICT = {
    'rc': '0',
    'result': {
        'something': 'Something happend',
        'items changed': {
            'item1': 'A',
            'item2': 'B',
            'item3': 'C'
        },
    },
    'backTolvl1':'text'
}

EXPECTED_MD_MULTI_DICT = """  * rc: 0
  * backTolvl1: text
  * ## Result
    * something: Something happend
    * ### Items Changed
      * item1: A
      * item2: B
      * item3: C
"""

MOCK_MULTI_LEVEL_LIST = [
    {'level1a': 'A',
     'level1b': 'B',
     'level1c': 'C'
     },
    {'1': ['a', 'b', 'c'], 'text': "audit log"},
    ["x", "y", "z"]
]

EXPECTED_MD_MULTI_LIST = """# List
  * level1a: A
  * level1b: B
  * level1c: C
# List
  * text: audit log
  * ## 1
    * 0: a
    * 1: b
    * 2: c
# List
  * 0: x
  * 1: y
  * 2: z
"""

MOCK_MULTI_LEVEL_LIST_ID_NAMES = [
    {'level1a': 'A',
     'level1b': 'B',
     'level1c': 'C'
     },
    {'1': ['a', 'b', 'c'], 'id': "id12345"},
    {'item1': 'abc',
     'name': 'xyz'}
]

EXPECTED_MD_MULTI_LIST_ID_NAMES = """# List
  * level1a: A
  * level1b: B
  * level1c: C
# Id12345
  * id: id12345
  * ## 1
    * 0: a
    * 1: b
    * 2: c
# Xyz
  * item1: abc
  * name: xyz
"""
