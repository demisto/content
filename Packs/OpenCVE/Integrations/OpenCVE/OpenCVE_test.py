import pytest
from OpenCVE import *
from CommonServerPython import *

OPEN_CVE = OpenCVE(tlp="red")
CLIENT = Client(server_url='https://www.opencve.io/api/', verify=False, proxy=False, auth=False)


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


@pytest.mark.parametrize("response, expected, args, mock_url",
                         [(util_load_json('test_data/reports_response.json'),
                           CommandResults(outputs=[{'id': 'KLMHU9EB4N8C',
                                                    'created_at': '2023-08-02T09:52:47Z',
                                                    'details': ['microsoft']},
                                                   {'id': 'NZSBGGBLW4TH',
                                                    'created_at': '2023-08-02T07:11:31Z',
                                                    'details': ['microsoft']}],
                                          outputs_prefix='OpenCVE.Reports'),
                           {},
                           'https://www.opencve.io/api/reports'),
                          (util_load_json('test_data/single_report_response.json'),
                           CommandResults(outputs=util_load_json('test_data/single_report_response.json'),
                                          outputs_prefix='OpenCVE.Reports.KLMHU9EB4N8C'),
                           {'report_id': 'KLMHU9EB4N8C'},
                           'https://www.opencve.io/api/reports/KLMHU9EB4N8C')])
def test_get_reports_command(response, expected, args, mock_url, requests_mock):
    requests_mock.get(mock_url, json=response)
    result = get_reports_command(CLIENT, args=args)
    assert result.outputs == expected.outputs
    assert result.outputs_prefix == expected.outputs_prefix


@pytest.mark.parametrize("response, args, expected, mock_url",
                         [(util_load_json('test_data/vendors_specific_vendor.json'),
                           {'vendor_name': 'paloaltonetworks'},
                           CommandResults(outputs=util_load_json('test_data/vendors_specific_vendor.json'),
                                          outputs_prefix='OpenCVE.paloaltonetworks'),
                           'https://www.opencve.io/api/vendors/paloaltonetworks'),
                          (util_load_json('test_data/vendors.json'),
                           {'search': 'search', 'letter': 'a', 'page': 1},
                           CommandResults(outputs=util_load_json('test_data/vendors.json'),
                                          outputs_prefix='OpenCVE.Vendors'),
                           'https://www.opencve.io/api/vendors')])
def test_get_vendors_command(response, args, expected, mock_url, requests_mock):
    requests_mock.get(mock_url, json=response)
    result = get_vendors_command(CLIENT, args=args)
    assert result.outputs == expected.outputs
    assert result.outputs_prefix == expected.outputs_prefix


@pytest.mark.parametrize("response, expected, mock_url",
                         [(util_load_json('test_data/my_vendors.json'),
                           CommandResults(outputs=util_load_json('test_data/my_vendors.json'),
                                          outputs_prefix='OpenCVE.myVendors'),
                           'https://www.opencve.io/api/account/subscriptions/vendors')])
def test_get_my_vendors_command(response, expected, mock_url, requests_mock):
    requests_mock.get(mock_url, json=response)
    result = get_my_vendors_command(CLIENT)
    assert result.outputs == expected.outputs
    assert result.outputs_prefix == expected.outputs_prefix


@pytest.mark.parametrize("response, expected, mock_url",
                         [(util_load_json('test_data/my_products.json'),
                           CommandResults(outputs=util_load_json('test_data/my_products.json'),
                                          outputs_prefix='OpenCVE.myProducts'),
                           'https://www.opencve.io/api/account/subscriptions/products')])
def test_get_my_products_command(response, expected, mock_url, requests_mock):
    requests_mock.get(mock_url, json=response)
    result = get_my_products_command(CLIENT)
    assert result.outputs == expected.outputs
    assert result.outputs_prefix == expected.outputs_prefix

    # Tests that the method returns the correct value when the input needle is a key in self.maps


@pytest.mark.parametrize("input, expected", [('HIGH', 'High (H)'), ('REQUIRED', 'Required (R)'),
                                             ('TEMPORARY_FIX', 'Temporary Fix (T)'), ('Unknown_key', 'Unknown_key')])
def test_existing_key(input, expected):
    obj = OpenCVE('white')
    assert obj._map(input) == expected


@pytest.mark.parametrize("expected", [(['CVE-2021-28478', 'CVE-2021-26418'])])
def test_cve_latest_command(expected, requests_mock):
    requests_mock.get('https://www.opencve.io/api/reports',
                      json=util_load_json('test_data/reports_response.json'))
    requests_mock.get('https://www.opencve.io/api/reports/KLMHU9EB4N8C/alerts',
                      json=util_load_json('test_data/KLMHU9EB4N8C_alerts.json'))
    requests_mock.get('https://www.opencve.io/api/reports/NZSBGGBLW4TH/alerts',
                      json=util_load_json('test_data/NZSBGGBLW4TH_alerts.json'))
    requests_mock.get('https://www.opencve.io/api/cve/CVE-2021-28478',
                      json=util_load_json('test_data/CVE-2021-28478.json'))
    requests_mock.get('https://www.opencve.io/api/cve/CVE-2021-26418',
                      json=util_load_json('test_data/CVE-2021-26418.json'))
    result = cve_latest_command(CLIENT, OPEN_CVE, {'last_run': '2023-08-01T02:00:00'})
    cves = [cve["value"] for cve in result.outputs]
    assert all(cve in expected for cve in cves)


@pytest.mark.parametrize("args, mock_url, mock_json",
                         [({'report_id': 'KLMHU9EB4N8C',
                            'alert_id': '475fde88-00dc-4024-9499-8197e334dfe7'},
                           'https://www.opencve.io/api/reports/KLMHU9EB4N8C/alerts/475fde88-00dc-4024-9499-8197e334dfe7',
                           util_load_json(
                             'test_data/alert_475fde88-00dc-4024-9499-8197e334dfe7.json')),
                          ({'report_id': 'KLMHU9EB4N8C'},
                           'https://www.opencve.io/api/reports/KLMHU9EB4N8C/alerts',
                           util_load_json('test_data/alerts_KLMHU9EB4N8C.json'))])
def test_get_alerts_command(args, mock_url, mock_json, requests_mock):
    requests_mock.get(mock_url, json=mock_json)
    alerts = get_alerts_command(CLIENT, args)
    assert alerts.outputs == mock_json


def test_get_alert_failed_commad():
    with pytest.raises(SystemExit):
        get_alerts_command(CLIENT, {})


@pytest.mark.parametrize("args, mock_url, mock_json, expected",
                         [({'cve': 'CVE-2021-26418'}, 'https://www.opencve.io/api/cve/CVE-2021-26418',
                           util_load_json('test_data/CVE-2021-26418.json'),
                           util_load_json('test_data/get_cve_command_outputs.json'))])
def test_get_cve_command(args, mock_url, mock_json, expected, requests_mock):
    requests_mock.get(mock_url, json=mock_json)
    cve = get_cve_command(CLIENT, OPEN_CVE, args)
    assert cve[0].outputs == expected


@pytest.mark.parametrize("response, expected", [({}, 'ok')])
def test_invalid_command_raises_error(mocker, requests_mock, response, expected):
    mocker.patch.object(demisto, 'params', return_value={'url': 'https://www.opencve.io',
                                                         'insecure': False,
                                                         'proxy': False,
                                                         'tlp_color': 'RED',
                                                         'credentials': {'identifier': 'user',
                                                                         'password': 'pass'}})
    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch.object(demisto, 'results')
    requests_mock.get('https://www.opencve.io/api/account/subscriptions/vendors', json=response)
    main()
    results = demisto.results.call_args[0]
    assert results[0] == expected


def test_failed_request(mocker):
    mocker.patch.object(demisto, "error")
    with pytest.raises(Exception):
        module_test_command(CLIENT)
