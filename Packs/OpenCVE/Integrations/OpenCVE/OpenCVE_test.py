import pytest
from CommonServerPython import *
from OpenCVE import *


OPEN_CVE = OpenCVE(tlp="red")


def util_load_json(path: str):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def assert_nested_dicts_equal(input, expected):
    """Asserts a complex indicator structure from XSOAR (after `to_context()`)

    Args:
        input (dict): Input
        expected (dict): Expected output
    """
    if isinstance(input, dict) and isinstance(expected, dict):
        assert set(input.keys()) == set(expected.keys()), "Keys in dictionaries are not equal."
        for key in input:
            assert_nested_dicts_equal(input[key], expected[key])

    elif isinstance(input, list) and isinstance(expected, list):
        try:
            for node1, node2 in zip(sorted(input), sorted(expected)):
                assert_nested_dicts_equal(node1, node2)

        except TypeError:
            sorted_list1 = sorted(input, key=lambda x: sorted(x.items()))
            sorted_list2 = sorted(expected, key=lambda x: sorted(x.items()))
            for node1, node2 in zip(sorted_list1, sorted_list2):
                assert_nested_dicts_equal(node1, node2)

    else:
        assert input == expected, "Values in dictionaries are not equal."


test_cases = [
    # Test case 1: Empty input nodes list
    ([], []),

    # Test case 2: One node with no CPE matches
    ([{"children": [], "cpe_match": []}], []),

    # Test case 3: One node with a vulnerable CPE match
    ([{"children": [], "cpe_match": [{"cpe23Uri": "cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*", "vulnerable": True}]}],
     ["cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*"]),

    # Test case 4: Multiple nodes with multiple CPE matches
    ([
        {"children": [], "cpe_match": [{"cpe23Uri": "cpe:2.3:a:vendor1:product1:1.0:*:*:*:*:*:*", "vulnerable": True}]},
        {"children": [], "cpe_match": [{"cpe23Uri": "cpe:2.3:a:vendor1:product1:2.0:*:*:*:*:*:*", "vulnerable": True}]},
        {"children": [], "cpe_match": [{"cpe23Uri": "cpe:2.3:a:vendor2:product2:3.0:*:*:*:*:*:*", "vulnerable": True}]}
    ],
        [
        "cpe:2.3:a:vendor1:product1:1.0:*:*:*:*:*:*",
            "cpe:2.3:a:vendor1:product1:2.0:*:*:*:*:*:*",
            "cpe:2.3:a:vendor2:product2:3.0:*:*:*:*:*:*"
    ]),

    # Node with children
    (
        [{
            "children": [
                {
                    "children": [], "operator": "OR",
                    "cpe_match": [
                        {
                                    "cpe23Uri": "cpe:2.3:o:siemens:sppa-t3000_ses3000_firmware:*:*:*:*:*:*:*:*",
                                    "cpe_name": [],
                                    "vulnerable": True
                        }
                    ]
                },
                {
                    "children": [], "operator": "OR",
                    "cpe_match": [
                        {
                                    "cpe23Uri": "cpe:2.3:h:siemens:sppa-t3000_ses3000:-:*:*:*:*:*:*:*",
                                    "cpe_name": [],
                                    "vulnerable": False
                        }
                    ]
                }
            ],
            "operator": "AND", "cpe_match": []
        }],
        [
            "cpe:2.3:o:siemens:sppa-t3000_ses3000_firmware:*:*:*:*:*:*:*:*"
        ]
    ),

    # Real CVE test (CVE-2019-0708)
    ([

        {"children": [], "operator": "OR", "cpe_match": [
            {"cpe23Uri": "cpe:2.3:o:microsoft:windows_vista:-:sp2:*:*:*:*:*:*", "cpe_name": [], "vulnerable": True},
            {"cpe23Uri": "cpe:2.3:o:microsoft:windows_server_2008:r2:sp1:*:*:*:*:x64:*", "cpe_name": [], "vulnerable": True},
            {"cpe23Uri": "cpe:2.3:o:microsoft:windows_server_2008:r2:sp1:*:*:*:*:itanium:*", "vulnerable": True},
            {"cpe23Uri": "cpe:2.3:o:microsoft:windows_server_2008:-:sp2:*:*:*:*:*:*", "cpe_name": [], "vulnerable": True},
            {"cpe23Uri": "cpe:2.3:o:microsoft:windows_xp:-:sp2:*:*:professional:*:x64:*", "cpe_name": [], "vulnerable": True},
            {"cpe23Uri": "cpe:2.3:o:microsoft:windows_xp:-:sp3:*:*:*:*:x86:*", "cpe_name": [], "vulnerable": True},
            {"cpe23Uri": "cpe:2.3:o:microsoft:windows_server_2003:-:sp2:*:*:*:*:x86:*", "cpe_name": [], "vulnerable": True},
            {"cpe23Uri": "cpe:2.3:o:microsoft:windows_server_2003:-:sp2:*:*:*:*:x64:*", "cpe_name": [], "vulnerable": True},
            {"cpe23Uri": "cpe:2.3:o:microsoft:windows_server_2003:r2:sp2:*:*:*:*:*:*", "cpe_name": [], "vulnerable": True},
            {"cpe23Uri": "cpe:2.3:o:microsoft:windows_7:-:sp1:*:*:*:*:*:*", "cpe_name": [], "vulnerable": True}
        ]
        }

    ],
        [
        "cpe:2.3:o:microsoft:windows_server_2008:-:sp2:*:*:*:*:*:*",
            "cpe:2.3:o:microsoft:windows_server_2003:-:sp2:*:*:*:*:x86:*",
            "cpe:2.3:o:microsoft:windows_server_2008:r2:sp1:*:*:*:*:x64:*",
            "cpe:2.3:o:microsoft:windows_xp:-:sp3:*:*:*:*:x86:*",
            "cpe:2.3:o:microsoft:windows_7:-:sp1:*:*:*:*:*:*",
            "cpe:2.3:o:microsoft:windows_server_2003:-:sp2:*:*:*:*:x64:*",
            "cpe:2.3:o:microsoft:windows_server_2008:r2:sp1:*:*:*:*:itanium:*",
            "cpe:2.3:o:microsoft:windows_xp:-:sp2:*:*:professional:*:x64:*",
            "cpe:2.3:o:microsoft:windows_server_2003:r2:sp2:*:*:*:*:*:*",
            "cpe:2.3:o:microsoft:windows_vista:-:sp2:*:*:*:*:*:*"
    ]
    ),
]


@pytest.mark.parametrize("nodes, expected", test_cases)
def test_parse_cpes(nodes, expected):
    cpes = [cpe.cpe for cpe in parse_cpes(nodes)]
    assert sorted(cpes) == sorted(expected)


@pytest.mark.parametrize("response, expected",
                         [(util_load_json('test_data/CVE-2019-0708.json'),
                           {'ID': 'CVE-2019-0708',
                            'CVSS Score': 9.8,
                            'Published': '2019-05-16T19:29:00Z',
                            'Modified': '2021-06-03T18:15:00Z',
                            'Description': "A remote code execution vulnerability exists in Remote Desktop Services formerly known as Terminal Services when an unauthenticated attacker connects to the target system using RDP and sends specially crafted requests, aka 'Remote Desktop Services Remote Code Execution Vulnerability'."  # noqa: E501
                            }
                           )
                          ]
                         )
def test_cve_to_warroom(response, expected):
    parsed_cve = parse_cve(OPEN_CVE, response)
    warroom_output = cve_to_warroom(parsed_cve)
    assert warroom_output == expected


@pytest.mark.parametrize("input, expected", [("CVE-2021-44228", True),
                                             ("CVEM-2021-44228", False)])
def test_valid_cve_format(input, expected):
    assert valid_cve_format(input) == expected


@pytest.mark.parametrize("response, expected", [(util_load_json('test_data/CVE-2019-0708.json'),
                                                 (util_load_json('test_data/parsed_Cve.json')))])
def test_parse_cve(response, expected):
    parsed_cve = parse_cve(OPEN_CVE, response)
    parsed_cve_relationships = [json.dumps(relationship.to_context()) for relationship in parsed_cve['fields']['relationships']]
    expected_relationships = [json.dumps(relationship) for relationship in expected['fields']['relationships']]
    assert sorted(parsed_cve_relationships) == sorted(expected_relationships)
    assert parsed_cve['fields']['cvssvector'] == expected['fields']['cvssvector']
    assert parsed_cve['fields']['cvssscore'] == expected['fields']['cvssscore']


@pytest.mark.parametrize("input, expected", [(util_load_json('test_data/CVE-2019-0708.json'),
                                              ["Windows vista", "Windows 7", "Windows server 2008",
                                               "Windows server 2003", "Windows xp", "Microsoft", "CWE-416"])])
def test_parse_tags(input, expected):
    relationships, tags = parse_tags(vendors=input['vendors'], cve_id=input['id'], cwes=input['cwes'])
    assert sorted(tags) == sorted(expected)


@pytest.mark.parametrize("input, expected", [([{'value': 'CVE-2019-0708'}, {'value': 'CVE-2019-0708'}],
                                              [{'value': 'CVE-2019-0708'}])])
def test_dedupe_cves(input, expected):
    assert dedupe_cves(input) == expected


@pytest.mark.parametrize("input, expected", [(util_load_json('test_data/CVE-2019-0708.json'),
                                              util_load_json('test_data/indicator.json'))])
def test_cve_to_indicator(input, expected):
    parsed_cve = parse_cve(OPEN_CVE, input)
    indicator = cve_to_indicator(ocve=OPEN_CVE, cve=parsed_cve)
    assert_nested_dicts_equal(indicator.to_context(), expected)
